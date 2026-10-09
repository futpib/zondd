import 'package:flutter/material.dart';
import 'connections.dart';
import 'ui.dart';
export 'connections.dart';
export 'dashboard.dart';

void main() => runApp(const ZonddApp());

class ZonddApp extends StatelessWidget {
  const ZonddApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'zondd',
    debugShowCheckedModeBanner: false,
    theme: appTheme(Brightness.light),
    darkTheme: appTheme(Brightness.dark),
    themeMode: ThemeMode.dark,
    home: const ConnectionsPage(),
  );
}
