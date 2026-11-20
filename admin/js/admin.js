/**
 * ShieldScope — admin controller.
 *
 * Implements:
 *  - Start / pause / resume / abort buttons
 *  - A tick loop that sends AJAX "chunk" requests while the scan is running;
 *    with background scanning on, WP-Cron also runs chunks when the tab is closed
 *  - Optional pause on blur / visibilitychange (only when background scanning is off)
 *  - Per-check progress list, stalled-scan and error messages
 *
 * @package ShieldScope
 */

( function ( $ ) {
	'use strict';

	if ( typeof window.ShieldScope === 'undefined' ) {
		return;
	}

	var cfg = window.ShieldScope;
	var $panel = $( '#shieldscope-scan-panel' );
	if ( ! $panel.length ) {
		return;
	}

	var tickTimer = null;
	var pollTimer = null;
	var inFlight  = false;
	var nextTickAt = 0; // Date.now() before which no tick is sent (server-requested rest).
	var lastStatus = $panel.data( 'status' ) || 'idle';
	var awaitingResume = false; // user-intent flag: scan should continue once tab refocused.
	var failures   = 0; // consecutive failed tick requests.
	var MAX_FAILURES = 5;
	var $bar       = $( '#shieldscope-progress-bar' );
	var $checks    = $( '#shieldscope-check-list' );

	var $status    = $( '#shieldscope-status-text' );
	var $msg       = $( '#shieldscope-message' );
	var $fill      = $( '#shieldscope-progress-fill' );
	var $pct       = $( '#shieldscope-progress-pct' );
	var $steps     = $( '#shieldscope-progress-steps' );
	var $summary   = $( '#shieldscope-summary' );
	var $btnStart  = $( '#shieldscope-btn-start' );
	var $btnPause  = $( '#shieldscope-btn-pause' );
	var $btnResume = $( '#shieldscope-btn-resume' );
	var $btnAbort  = $( '#shieldscope-btn-abort' );

	// Friendly focus-loss banner + title handling.
	var $blurBanner = $( '#shieldscope-blur-banner' );
	var $blurTitle  = $( '#shieldscope-blur-title' );
	var $blurBody   = $( '#shieldscope-blur-body' );
	var originalTitle = document.title;

	function setDocTitle( key ) {
		if ( cfg.i18n && cfg.i18n[ key ] ) {
			document.title = cfg.i18n[ key ];
		} else {
			document.title = originalTitle;
		}
	}

	function showBlurBanner() {
		$blurTitle.text( cfg.i18n.blurTitle || '' );
		$blurBody.text( cfg.i18n.blurBody || '' );
		$blurBanner.prop( 'hidden', false ).addClass( 'is-visible' );
	}

	function hideBlurBanner() {
		$blurBanner.removeClass( 'is-visible' ).prop( 'hidden', true );
	}

	function setButtons( status ) {
		$( '#shieldscope-btn-quick' ).prop( 'disabled', 'running' === status || 'paused' === status );
		switch ( status ) {
			case 'running':
				$btnStart.prop( 'disabled', true );
				$btnPause.prop( 'disabled', false );
				$btnResume.prop( 'disabled', true );
				$btnAbort.prop( 'disabled', false );
				break;
			case 'paused':
				$btnStart.prop( 'disabled', true );
				$btnPause.prop( 'disabled', true );
				$btnResume.prop( 'disabled', false );
				$btnAbort.prop( 'disabled', false );
				break;
			case 'completed':
			case 'aborted':
			case 'idle':
			default:
				$btnStart.prop( 'disabled', false );
				$btnPause.prop( 'disabled', true );
				$btnResume.prop( 'disabled', true );
				$btnAbort.prop( 'disabled', true );
				break;
		}
	}

	function updateUI( data ) {
		if ( ! data ) {
			return;
		}
		lastStatus = data.status || lastStatus;

		$status.text( data.status.charAt( 0 ).toUpperCase() + data.status.slice( 1 ) );
		$msg.text( data.message || '' );

		var pct = parseInt( data.progress, 10 ) || 0;
		$fill.css( 'width', pct + '%' );
		$pct.text( pct + '%' );
		$bar.attr( 'aria-valuenow', pct );
		$steps.text(
			cfg.i18n.stepsOf
				.replace( '%1$d', data.done_steps || 0 )
				.replace( '%2$d', data.total_steps || 0 )
		);
		if ( data.stalled ) {
			$msg.text( cfg.i18n.stalled );
		}
		renderChecks( data.checks );

		if ( data.summary ) {
			$summary.removeClass( 'shieldscope-hidden' );
			$summary.find( '.count' ).each( function () {
				var sev = $( this ).data( 'sev' );
				$( this ).text( data.summary[ sev ] || 0 );
			} );
		}

		// Keep the tab title accurate so the user sees state from other tabs.
		if ( 'running' === lastStatus ) {
			if ( isTabActive() ) {
				setDocTitle( 'titleActive' );
			}
		} else if ( 'paused' === lastStatus ) {
			setDocTitle( 'titlePaused' );
		} else if ( 'completed' === lastStatus ) {
			setDocTitle( 'titleDone' );
			hideBlurBanner();
		} else if ( 'aborted' === lastStatus || 'idle' === lastStatus ) {
			document.title = originalTitle;
			hideBlurBanner();
		}

		setButtons( lastStatus );
	}

	function renderChecks( checks ) {
		if ( ! $checks.length || ! checks || ! checks.length ) {
			return;
		}
		$checks.empty();
		checks.forEach( function ( c ) {
			var $li = $( '<li>' ).addClass( 'is-' + c.status );
			$( '<span class="shieldscope-check-name">' ).text( c.label ).appendTo( $li );
			$( '<span class="shieldscope-check-status">' ).text( ( cfg.i18n.checkStatus && cfg.i18n.checkStatus[ c.status ] ) || c.status ).appendTo( $li );
			if ( c.notes && c.notes.length ) {
				$( '<span class="shieldscope-check-notes">' ).text( c.notes.join( '; ' ) ).appendTo( $li );
			}
			$checks.append( $li );
		} );
		$checks.closest( '.shieldscope-checks-card' ).removeClass( 'shieldscope-hidden' );
	}

	function ajax( action, extra ) {
		return $.ajax( {
			url: cfg.ajaxUrl,
			method: 'POST',
			dataType: 'json',
			data: $.extend( {
				action: 'shieldscope_' + action,
				_wpnonce: cfg.nonce
			}, extra || {} )
		} );
	}

	function tick() {
		if ( inFlight ) {
			return;
		}
		// Rest the server asked for after the last chunk (scan pace).
		if ( Date.now() < nextTickAt ) {
			return;
		}
		// Only run work chunks while the tab is visible and focused.
		if ( cfg.pauseOnBlur && ! isTabActive() ) {
			return;
		}
		if ( 'running' !== lastStatus ) {
			return;
		}

		inFlight = true;
		ajax( 'tick' )
			.done( function ( resp ) {
				failures = 0;
				if ( resp && resp.success ) {
					nextTickAt = Date.now() + Math.min( 30000, Math.max( 0, parseInt( resp.data.rest_ms, 10 ) || 0 ) );
					updateUI( resp.data );
					if ( 'completed' === resp.data.status ) {
						$msg.text( cfg.i18n.finished );
						stopLoops();
					} else if ( 'aborted' === resp.data.status ) {
						stopLoops();
					}
				}
			} )
			.fail( function ( xhr ) {
				failures++;
				if ( xhr && 403 === xhr.status ) {
					$msg.text( cfg.i18n.expired );
					stopLoops();
					return;
				}
				if ( failures >= MAX_FAILURES ) {
					$msg.text( cfg.i18n.gaveUp );
					stopTicks();
					return;
				}
				// Back off a little more after each failure.
				nextTickAt = Date.now() + failures * 3000;
				$msg.text( cfg.i18n.error );
			} )
			.always( function () {
				inFlight = false;
			} );
	}

	function poll() {
		if ( inFlight ) {
			return;
		}
		inFlight = true;
		ajax( 'status' )
			.done( function ( resp ) {
				if ( resp && resp.success ) {
					updateUI( resp.data );
				}
			} )
			.always( function () {
				inFlight = false;
			} );
	}

	function startLoops() {
		stopLoops();
		tickTimer = window.setInterval( tick, cfg.tickInterval );
		pollTimer = window.setInterval( poll, cfg.pollInterval );
	}

	function stopTicks() {
		if ( tickTimer ) {
			window.clearInterval( tickTimer );
			tickTimer = null;
		}
	}

	function stopLoops() {
		if ( tickTimer ) {
			window.clearInterval( tickTimer );
			tickTimer = null;
		}
		if ( pollTimer ) {
			window.clearInterval( pollTimer );
			pollTimer = null;
		}
	}

	function isTabActive() {
		if ( 'undefined' !== typeof document.hidden ) {
			if ( document.hidden ) {
				return false;
			}
		}
		if ( 'undefined' !== typeof document.hasFocus ) {
			return document.hasFocus();
		}
		return true;
	}

	// --- Button handlers --- .

	var $btnQuick = $( '#shieldscope-btn-quick' );

	function startScan( quick ) {
		$btnStart.prop( 'disabled', true );
		$btnQuick.prop( 'disabled', true );
		$msg.text( cfg.i18n.starting );
		ajax( 'start', quick ? { quick: 1 } : {} )
			.done( function ( resp ) {
				if ( resp && resp.success ) {
					failures = 0;
					updateUI( resp.data );
					awaitingResume = true;
					startLoops();
				} else {
					$btnStart.prop( 'disabled', false );
					$btnQuick.prop( 'disabled', false );
				}
			} )
			.fail( function ( xhr ) {
				$msg.text( xhr && 403 === xhr.status ? cfg.i18n.expired : cfg.i18n.error );
				$btnStart.prop( 'disabled', false );
				$btnQuick.prop( 'disabled', false );
			} );
	}

	$btnStart.on( 'click', function () {
		startScan( false );
	} );
	$btnQuick.on( 'click', function () {
		startScan( true );
	} );

	$btnPause.on( 'click', function () {
		ajax( 'pause' ).done( function ( resp ) {
			if ( resp && resp.success ) {
				updateUI( resp.data );
				awaitingResume = false;
			}
		} );
	} );

	$btnResume.on( 'click', function () {
		ajax( 'resume' ).done( function ( resp ) {
			if ( resp && resp.success ) {
				failures   = 0;
				nextTickAt = 0;
				updateUI( resp.data );
				awaitingResume = true;
				startLoops();
			}
		} );
	} );

	$btnAbort.on( 'click', function () {
		if ( ! window.confirm( cfg.i18n.confirmAbort ) ) {
			return;
		}
		ajax( 'abort' ).done( function ( resp ) {
			if ( resp && resp.success ) {
				updateUI( resp.data );
				awaitingResume = false;
				stopLoops();
			}
		} );
	} );

	// --- Focus / visibility handling — the "keep user on the tab" behavior --- .

	function onFocusLost() {
		if ( ! cfg.pauseOnBlur ) {
			return;
		}
		if ( 'running' === lastStatus ) {
			// Immediately flip the tab title so the user sees the pause from the tab bar.
			setDocTitle( 'titlePaused' );
			// Ask server to pause so no more work happens.
			ajax( 'pause' ).done( function ( resp ) {
				if ( resp && resp.success ) {
					updateUI( resp.data );
					$msg.text( cfg.i18n.paused );
					awaitingResume = true; // Remember: auto-resume on focus.
				}
			} );
		}
	}

	function onFocusGained() {
		hideBlurBanner();
		if ( ! cfg.pauseOnBlur ) {
			return;
		}
		// Auto-resume only if the user had started a scan and hadn't manually paused it.
		if ( awaitingResume && 'paused' === lastStatus ) {
			ajax( 'resume' ).done( function ( resp ) {
				if ( resp && resp.success ) {
					updateUI( resp.data );
					$msg.text( cfg.i18n.resumed );
					setDocTitle( 'titleActive' );
					startLoops();
				}
			} );
		} else if ( 'running' !== lastStatus ) {
			// Restore the default title when nothing is running.
			document.title = originalTitle;
		}
	}

	$( window ).on( 'blur', function () {
		if ( cfg.pauseOnBlur && 'running' === lastStatus ) {
			showBlurBanner();
		}
		onFocusLost();
	} );
	$( window ).on( 'focus', onFocusGained );
	document.addEventListener( 'visibilitychange', function () {
		if ( document.hidden ) {
			if ( cfg.pauseOnBlur && 'running' === lastStatus ) {
				showBlurBanner();
			}
			onFocusLost();
		} else {
			onFocusGained();
		}
	} );

	// Warn on leave while running.
	window.addEventListener( 'beforeunload', function ( e ) {
		// With background scanning the scan carries on without this page.
		if ( ! cfg.background && ( 'running' === lastStatus || 'paused' === lastStatus ) ) {
			e.preventDefault();
			e.returnValue = cfg.i18n.leaveWarn;
			return cfg.i18n.leaveWarn;
		}
	} );

	// Resume loops on page load if state was already active.
	if ( 'running' === lastStatus ) {
		awaitingResume = true;
		startLoops();
	} else if ( 'paused' === lastStatus ) {
		// Poll so the UI stays in sync but don't auto-resume — user paused deliberately.
		pollTimer = window.setInterval( poll, cfg.pollInterval );
	}

	// Initial state render.
	setButtons( lastStatus );

	// Kick off an initial status fetch so summary populates on reload.
	if ( $panel.data( 'scan-id' ) ) {
		poll();
	}
} )( jQuery );
