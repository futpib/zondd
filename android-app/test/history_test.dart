import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/history.dart';
import 'package:zondd_control/json_yaml.dart';

class HistoryControl implements ControlApi {
  int count = 1;
  final calls = <Map<String, dynamic>>[];
  Completer<void>? holdNext;
  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    calls.add(body);
    final hold = holdNext;
    holdNext = null;
    final activity = body['method'] == 'actions';
    expect(body['method'], anyOf('history', 'actions'));
    final before = body['before'] as int? ?? count + 1;
    final rows =
        [
              for (var i = count; i > 0; i--)
                if (i < before)
                  if (activity)
                    {
                      'sequence': i,
                      'action': 'event-$i',
                      'time_unix_ms': 0,
                      'detail': {'message': i == 1 ? 'older-needle' : 'recent'},
                    }
                  else
                    {
                      'sequence': i,
                      'request_id': '$i',
                      'principal': 'caller-$i',
                      'status': i == 1
                          ? (count == 1 ? 'pending' : 'completed')
                          : 'expired',
                      'command': {
                        'program': '/usr/bin/true',
                        'args': [i == 1 ? 'older-needle' : 'recent'],
                      },
                      'reason': 'approval expired',
                      'created_unix_ms': 0,
                    },
            ]
            .where(
              (row) =>
                  body['query'] == null ||
                  '${jsonAsYaml(row)} ${activity ? '' : statusLabel(row['status'] as String)}'
                      .toLowerCase()
                      .contains((body['query'] as String).toLowerCase()),
            )
            .take(body['limit'] as int)
            .toList();
    await hold?.future;
    return {
      activity ? 'actions' : 'requests': rows,
      'next_before': rows.length == body['limit']
          ? rows.last['sequence']
          : null,
    };
  }
}

void main() {
  testWidgets(
    'search reaches older requests and activity, and clearing resets pagination',
    (tester) async {
      final api = HistoryControl()..count = 65;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: HistoryPage(api: api)),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Finished · caller-1'), findsNothing);
      await tester.enterText(find.byType(TextField), 'older-needle');
      await tester.pump(const Duration(milliseconds: 350));
      await tester.pumpAndSettle();
      expect(find.text('Finished · caller-1'), findsOneWidget);
      expect(api.calls.last, {
        'method': 'history',
        'limit': 30,
        'query': 'older-needle',
      });
      await tester.tap(find.text('Activity'));
      await tester.pumpAndSettle();
      expect(find.text('event-1'), findsOneWidget);
      expect(find.byType(SelectableText), findsNothing);
      await tester.tap(find.text('event-1'));
      await tester.pumpAndSettle();
      expect(find.textContaining('message: older-needle'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'missing');
      await tester.pump(const Duration(milliseconds: 350));
      await tester.pumpAndSettle();
      expect(find.text('No history matches your search.'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'older-needle');
      await tester.pump(const Duration(milliseconds: 350));
      await tester.pumpAndSettle();
      expect(find.textContaining('message: older-needle'), findsOneWidget);
      await tester.tap(find.byTooltip('Clear search'));
      await tester.pump(const Duration(milliseconds: 350));
      await tester.pumpAndSettle();
      expect(find.text('event-65'), findsOneWidget);
      expect(api.calls.last.containsKey('query'), isFalse);
      expect(api.calls.last.containsKey('before'), isFalse);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('a delayed response cannot overwrite a newer search', (
    tester,
  ) async {
    final api = HistoryControl();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: HistoryPage(api: api)),
      ),
    );
    await tester.pumpAndSettle();
    final hold = Completer<void>();
    api.holdNext = hold;
    await tester.enterText(find.byType(TextField), 'missing');
    await tester.pump(const Duration(milliseconds: 350));
    await tester.enterText(find.byType(TextField), 'older-needle');
    await tester.pump(const Duration(milliseconds: 350));
    hold.complete();
    await tester.pumpAndSettle();
    expect(find.text('Needs approval · caller-1'), findsOneWidget);
    expect(find.text('No history matches your search.'), findsNothing);
    expect(api.calls.last['query'], 'older-needle');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'refresh removes an active request that no longer matches its status',
    (tester) async {
      final api = HistoryControl();
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: HistoryPage(api: api)),
        ),
      );
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'Needs approval');
      await tester.pump(const Duration(milliseconds: 350));
      await tester.pumpAndSettle();
      expect(find.text('Needs approval · caller-1'), findsOneWidget);
      api.count = 32;
      await tester.pump(const Duration(seconds: 2));
      await tester.pumpAndSettle();
      expect(find.text('No history matches your search.'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

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
        scrollable: find
            .descendant(
              of: find.byType(ListView),
              matching: find.byType(Scrollable),
            )
            .first,
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
