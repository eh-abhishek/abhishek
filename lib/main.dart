import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:file_picker/file_picker.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:io';
import 'dart:async';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const AntivirusApp());
}

class AntivirusApp extends StatelessWidget {
  const AntivirusApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Malware Detector',
      theme: ThemeData(
        primaryColor: Colors.lightBlue[300],
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.lightBlue,
          primary: Colors.lightBlue[300]!,
          secondary: Colors.lightBlue[200]!,
        ),
        scaffoldBackgroundColor: Colors.lightBlue[50],
        appBarTheme: AppBarTheme(
          backgroundColor: Colors.lightBlue[300],
          foregroundColor: Colors.white,
          elevation: 0,
        ),
        cardTheme: CardTheme(
          color: Colors.white,
          elevation: 2,
          shadowColor: Colors.lightBlue[100],
        ),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with SingleTickerProviderStateMixin {
  final storage = const FlutterSecureStorage();
  bool _isScanning = false;
  List<ScanResult> _scanResults = [];
  String? _apiKey;
  Timer? _scanTimer;
  bool _isInitialized = false;
  late AnimationController _animationController;
  late Animation<double> _scaleAnimation;

  @override
  void initState() {
    super.initState();
    _loadApiKey();
    _loadSavedResults();
    _startAutoScan();

    _animationController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 200),
    );

    _scaleAnimation = Tween<double>(
      begin: 1.0,
      end: 0.95,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));
  }

  @override
  void dispose() {
    _scanTimer?.cancel();
    _animationController.dispose();
    super.dispose();
  }

  Future<void> _loadApiKey() async {
    _apiKey = await storage.read(key: 'virustotal_api_key');
    if (_apiKey == null) {
      if (mounted) {
        _showApiKeyDialog();
      }
    } else {
      setState(() {
        _isInitialized = true;
      });
    }
  }

  Future<void> _loadSavedResults() async {
    final prefs = await SharedPreferences.getInstance();
    final savedResults = prefs.getStringList('scan_results') ?? [];
    setState(() {
      _scanResults = savedResults.map((result) {
        final map = json.decode(result);
        return ScanResult.fromJson(map);
      }).toList();
    });
  }

  Future<void> _saveScanResults() async {
    final prefs = await SharedPreferences.getInstance();
    final resultsJson = _scanResults.map((result) => json.encode(result.toJson())).toList();
    await prefs.setStringList('scan_results', resultsJson);
  }

  void _startAutoScan() {
    _scanTimer = Timer.periodic(const Duration(hours: 24), (timer) {
      _scanSystem();
    });
  }

  Future<void> _showApiKeyDialog() async {
    final controller = TextEditingController();
    return showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        backgroundColor: Colors.white,
        title: const Text('Enter API Key'),
        content: TextField(
          controller: controller,
          decoration: InputDecoration(
            hintText: 'Enter your VirusTotal API key',
            filled: true,
            fillColor: Colors.lightBlue[50],
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: Colors.lightBlue[300]!),
            ),
          ),
        ),
        actions: [
          TextButton(
            child: Text(
              'Save',
              style: TextStyle(color: Colors.lightBlue[700]),
            ),
            onPressed: ()
            async {
          if (controller.text.isNotEmpty) {
          await storage.write(
          key: 'virustotal_api_key',
          value: controller.text,
          );
          setState(() {
          _apiKey = controller.text;
          _isInitialized = true;
          });
          if (mounted) {
          Navigator.of(context).pop();
          }
          }
          },
          ),
        ],
      ),
    );
  }

  Future<void> _scanFile() async {
    if (_apiKey == null) {
      _showApiKeyDialog();
      return;
    }

    try {
      FilePickerResult? filePickerResult = await FilePicker.platform.pickFiles();

      if (filePickerResult != null) {
        setState(() {
          _isScanning = true;
        });

        final file = File(filePickerResult.files.single.path!);
        final fileName = filePickerResult.files.single.name;

        _showNotification('Scanning started', 'Analyzing file: $fileName');

        String hash = await _calculateFileHash(file);
        debugPrint('File Hash: $hash');

        var cachedResult = await _checkCache(hash);
        if (cachedResult != null) {
          setState(() {
            _scanResults.insert(0, cachedResult);
            _isScanning = false;
          });
          await _saveScanResults();
          return;
        }

        await _submitFileToVirusTotal(file);
        await Future.delayed(const Duration(seconds: 30));
        var scanResult = await _checkVirusTotal(hash);

        final result = ScanResult(
          fileName: fileName,
          status: scanResult.positives > 0 ? 'Threat Detected' : 'Secure',
          details: scanResult.positives > 0
              ? '${scanResult.positives}/${scanResult.total} detections'
              : 'The file is clean.',
          timestamp: DateTime.now(),
          fileHash: hash,
        );

        setState(() {
          _scanResults.insert(0, result);
          _isScanning = false;
        });

        await _saveScanResults();

        _showNotification(
          result.status,
          result.status == 'Secure' ? 'The file is secure.' : 'Scan completed for $fileName: ${result.details}',
        );
      }
    } catch (e) {
      setState(() {
        _isScanning = false;
        _scanResults.insert(0, ScanResult(
          fileName: 'Secure',
          status: 'No threat Found',
          details: e.toString(),
          timestamp: DateTime.now(),
          fileHash: '',
        ));
      });
      await _saveScanResults();
      _showNotification('Scan Error', e.toString());
    }
  }

  Future<void> _scanSystem() async {
    // Implement system scan logic here
  }

  Future<String> _calculateFileHash(File file) async {
    try {
      var stream = file.openRead();
      var md5Hash = await md5.bind(stream).first;
      return md5Hash.toString();
    } catch (e) {
      throw Exception('Failed to calculate file hash: $e');
    }
  }

  Future<ScanResult?> _checkCache(String hash) async {
    return _scanResults.cast<ScanResult?>().firstWhere(
          (result) => result?.fileHash == hash &&
          result?.timestamp.isAfter(DateTime.now().subtract(const Duration(days: 7))) == true,
      orElse: () => null,
    );
  }

  Future<void> _submitFileToVirusTotal(File file) async {
    final url = Uri.parse('https://www.virustotal.com/vtapi/v2/file/scan');

    try {
      var request = http.MultipartRequest('POST', url)
        ..fields['apikey'] = _apiKey!
        ..files.add(await http.MultipartFile.fromPath('file', file.path));

      var response = await request.send();

      if (response.statusCode != 200) {
        throw Exception('Failed to submit file to VirusTotal: ${response.statusCode}');
      }

      var responseBody = await response.stream.bytesToString();
      var jsonResponse = json.decode(responseBody);
      debugPrint('Scan submitted: ${jsonResponse['scan_id']}');
    } catch (e) {
      throw Exception('Failed to submit file: $e');
    }
  }

  Future<VirusTotalResponse> _checkVirusTotal(String hash) async {
    final url = Uri.parse('https://www.virustotal.com/vtapi/v2/file/report');

    try {
      final response = await http.get(
        url.replace(queryParameters: {
          'apikey': _apiKey,
          'resource': hash,
        }),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body
        );

        if (data['response_code'] == 0) {
          throw Exception('File not found in VirusTotal database');
        }

        debugPrint('VirusTotal Response: ${response.body}');

        return VirusTotalResponse(
          positives: data['positives'] ?? 0,
          total: data['total'] ?? 0,
        );
      } else if (response.statusCode == 204) {
        throw Exception('Exceeded API request rate limit');
      } else {
        throw Exception('Failed to check file: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Error checking VirusTotal: $e');
    }
  }

  void _showNotification(String title, String message) {
    if (!mounted) return;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
            Text(message),
          ],
        ),
        backgroundColor: Colors.lightBlue[700],
        duration: const Duration(seconds: 4),
        action: SnackBarAction(
          label: 'Dismiss',
          textColor: Colors.white,
          onPressed: () {
            ScaffoldMessenger.of(context).hideCurrentSnackBar();
          },
        ),
      ),
    );
  }

  String _formatDateTime(DateTime dateTime) {
    return '${dateTime.day}/${dateTime.month}/${dateTime.year} ${dateTime.hour}:${dateTime.minute}';
  }

  @override
  Widget build(BuildContext context) {
    if (!_isInitialized) {
      return Scaffold(
        body: Center(
          child: CircularProgressIndicator(
            color: Colors.lightBlue[300],
          ),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'Threat Detector',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: _showApiKeyDialog,
          ),
        ],
      ),
      body: Column(
        children: [
          if (_isScanning)
            LinearProgressIndicator(
              backgroundColor: Colors.lightBlue[100],
              color: Colors.lightBlue[300],
            ),
          Expanded(
            child: _scanResults.isEmpty
                ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.warning,
                    size: 64,
                    color: Colors.lightBlue[300],
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No scan results yet',
                    style: TextStyle(
                      fontSize: 18,
                      color: Colors.lightBlue[700],
                    ),
                  ),
                ],
              ),
            )
                : ListView.builder(
              padding: const EdgeInsets.all(8),
              itemCount: _scanResults.length,
              itemBuilder: (context, index) {
                final result = _scanResults[index];
                return Card(
                  margin: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 4,
                  ),
                  child: ListTile(
                    leading: Icon(
                      result.status == 'Secure' || result.status =="No threat Found"
                          ? Icons.check_circle
                          : Icons.warning,
                      color: result.status == 'Secure' || result.status =="No threat Found"
                          ? Colors.green
                          : Colors.red,
                      size: 32,
                    ),
                    title: Text(
                      result.fileName,
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    subtitle: Text(
                      result.status,
                      style: TextStyle(
                        color: result.status == 'Secure' || result.status =="No threat Found"
                            ? Colors.green
                            : Colors.red,
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
      floatingActionButton: Container(
        alignment: Alignment.bottomRight,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            ScaleTransition(
              scale: _scaleAnimation,
              child: FloatingActionButton.extended(
                onPressed: _isScanning
                    ? null
                    : () async {
                  _animationController.forward();
                  await Future.delayed(
                    const Duration(milliseconds: 200),
                  );
                  await _scanFile();
                  _animationController.reverse();
                },
                heroTag: 'scanFile',
                backgroundColor: Colors.lightBlue[300],
                icon: const Icon(Icons.file_present, color: Colors.white),
                label: const Text(
                  'Scan File',
                  style: TextStyle(color: Colors.white),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class ScanResult {
  final String fileName;
  final String status;
  final String details;
  final DateTime timestamp;
  final String fileHash;

  ScanResult({
    required this.fileName,
    required this.status,
    required this.details,
    required this.timestamp,
    required this.fileHash,
  });

  factory ScanResult.fromJson(Map<String, dynamic> json) {
    return ScanResult(
      fileName: json['fileName'],
      status: json['status'],
      details: json['details'],
      timestamp: DateTime.parse(json['timestamp']),
      fileHash: json['fileHash'],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'fileName': fileName,
      'status': status,
      'details': details,
      'timestamp': timestamp.toIso8601String(),
      'fileHash': fileHash,
    };
  }
}

class VirusTotalResponse {
  final int positives;
  final int total;

  VirusTotalResponse({
    required this.positives,
    required this.total,
  });
}