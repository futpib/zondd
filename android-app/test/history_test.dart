import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/history.dart';

class HistoryControl implements ControlApi {
  int count = 1;
  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    expect(body['method'], 'history');
    final before = body['before'] as int? ?? count + 1;
    final rows = [
      for (var i = count; i > 0; i--)
        if (i < before)
          {
            'sequence': i,
            'request_id': '$i',
            'principal': 'caller-$i',
            'status': i == 1
                ? (count == 1 ? 'pending' : 'completed')
                : 'expired',
            'command': {'program': '/usr/bin/true', 'args': []},
            'reason': 'approval expired',
            'created_unix_ms': 0,
          },
    ].take(body['limit'] as int).toList();
    return {
      'requests': rows,
      'next_before': rows.length == body['limit']
          ? rows.last['sequence']
          : null,
    };
  }
}

void main() {
  testWidgets(
    'history that grows beyond one page keeps older outcomes reachable',
    (tester) async {
      final api = HistoryControl();
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: HistoryPage(api: api)),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Needs approval · caller-1'), findsOneWidget);
      expect(find.text('Load earlier'), findsNothing);
      api.count = 32;
      await tester.pump(const Duration(seconds: 2));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(
        find.text('Load earlier'),
        500,
        maxScrolls: 50,
      );
      expect(find.text('Finished · caller-1'), findsOneWidget);
      await tester.tap(find.text('Load earlier'));
      await tester.pumpAndSettle();
      expect(find.text('Expired · caller-2'), findsOneWidget);
      expect(find.text('Load earlier'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
