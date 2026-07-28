import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

import '../../shared/relay/relay.dart';

/// In-memory cache of other users' presence.
///
/// Subscribes to kind:20001 presence events over the relay WebSocket for
/// real-time updates and hydrates newly tracked users from relay-synthesized
/// kind:40902 snapshots.
class PresenceCacheNotifier extends Notifier<Map<String, String>> {
  final Set<String> _tracked = {};
  void Function()? _presenceUnsub;
  int _subscriptionVersion = 0;

  @override
  Map<String, String> build() {
    final sessionState = ref.watch(relaySessionProvider);

    ref.onDispose(() {
      _presenceUnsub?.call();
      _presenceUnsub = null;
    });

    if (sessionState.status == SessionStatus.connected) {
      _subscribePresenceUpdates();
    }

    return {};
  }

  /// Track presence for [pubkeys].
  void track(List<String> pubkeys) {
    final normalized = pubkeys.map((pk) => pk.toLowerCase()).toList();
    final newlyTracked = normalized
        .where((pubkey) => !_tracked.contains(pubkey))
        .toList();
    _tracked.addAll(normalized);
    if (newlyTracked.isNotEmpty) {
      unawaited(_hydratePresence(newlyTracked));
    }
  }

  Future<void> _hydratePresence(List<String> pubkeys) async {
    try {
      final events = await ref.read(relaySessionProvider.notifier).queryRelay([
        NostrFilter(
          kinds: const [EventKind.presenceSnapshot],
          authors: pubkeys,
          limit: pubkeys.length,
        ),
      ]);
      for (final event in events) {
        _handlePresenceEvent(event, onlyIfAbsent: true);
      }
    } catch (error) {
      debugPrint('[PresenceCacheNotifier] presence snapshot failed: $error');
    }
  }

  /// Subscribe to kind:20001 presence events over WebSocket.
  Future<void> _subscribePresenceUpdates() async {
    _presenceUnsub?.call();
    _presenceUnsub = null;
    _subscriptionVersion++;
    final version = _subscriptionVersion;

    final session = ref.read(relaySessionProvider.notifier);
    try {
      final unsub = await session.subscribe(
        const NostrFilter(kinds: [EventKind.presenceUpdate], limit: 0),
        _handlePresenceEvent,
      );
      // Guard: if build() re-fired while we were awaiting, discard this
      // subscription to avoid leaking it.
      if (version != _subscriptionVersion) {
        unsub();
        return;
      }
      _presenceUnsub = unsub;
    } catch (error) {
      debugPrint(
        '[PresenceCacheNotifier] presence subscription failed: $error',
      );
    }
  }

  void _handlePresenceEvent(NostrEvent event, {bool onlyIfAbsent = false}) {
    final pubkey = (event.getTagValue('p') ?? event.pubkey).toLowerCase();
    if (!_tracked.contains(pubkey)) return;
    final status = event.content;
    if (status != 'online' && status != 'away' && status != 'offline') return;
    if (onlyIfAbsent && state.containsKey(pubkey)) return;
    if (state[pubkey] == status) return;
    final updated = Map<String, String>.from(state);
    updated[pubkey] = status;
    state = updated;
  }
}

final presenceCacheProvider =
    NotifierProvider<PresenceCacheNotifier, Map<String, String>>(
      PresenceCacheNotifier.new,
    );
