import 'package:buzz/features/channels/channel_management_provider.dart';
import 'package:buzz/features/channels/send_message_provider.dart';
import 'package:buzz/features/profile/user_profile.dart';
import 'package:buzz/shared/relay/relay.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('adds the persistent DM audience to message p tags', () async {
    final relay = _RecordingSignedEventRelay();
    final sendMessage = SendMessage(
      signedEventRelay: relay,
      fetchMembers: (_) async => const <ChannelMember>[],
      readUserCache: () => const <String, UserProfile>{},
    );

    await sendMessage(
      channelId: 'dm-channel',
      content: 'hello',
      mentionPubkeys: const [],
      audiencePubkeys: const ['self', 'frame', 'FRAME'],
    );

    expect(relay.tags, [
      ['h', 'dm-channel'],
      ['p', 'frame'],
    ]);
  });

  test('does not add audience tags to an ordinary channel send', () async {
    final relay = _RecordingSignedEventRelay();
    final sendMessage = SendMessage(
      signedEventRelay: relay,
      fetchMembers: (_) async => const <ChannelMember>[],
      readUserCache: () => const <String, UserProfile>{},
    );

    await sendMessage(
      channelId: 'stream-channel',
      content: 'hello',
      mentionPubkeys: const [],
    );

    expect(relay.tags, [
      ['h', 'stream-channel'],
    ]);
  });
}

class _RecordingSignedEventRelay implements SignedEventRelay {
  List<List<String>>? tags;

  @override
  String? get pubkey => 'self';

  @override
  Future<NostrEvent> submit({
    required int kind,
    required String content,
    required List<List<String>> tags,
    int? createdAt,
  }) async {
    this.tags = tags;
    return const NostrEvent(
      id: 'ack',
      pubkey: '',
      createdAt: 0,
      kind: 0,
      tags: [],
      content: '',
      sig: '',
    );
  }
}
