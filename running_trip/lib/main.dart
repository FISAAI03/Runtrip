import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const RunTripApp());
}

class RunTripApp extends StatelessWidget {
  const RunTripApp({super.key});

  @override
  Widget build(BuildContext context) {
    const bgColor = Color(0xFFF7F8FC);

    return MaterialApp(
      title: '러닝트립',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        scaffoldBackgroundColor: bgColor,
        fontFamily: 'Pretendard',
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

class _HomePageState extends State<HomePage> {
  final List<String> _cities = ['서울', '부산', '대구', '제주'];
  int _selectedCityIndex = 0;
  int _currentIndex = 0;

  @override
  Widget build(BuildContext context) {
    const navy = Color(0xFF102440);

    // 각 도시별 화면
    final List<Widget> cityPages = [
      const CityPage(city: '서울'),
      const CityPage(city: '부산'),
      const CityPage(city: '대구'),
      const CityPage(city: '제주'),
    ];

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(24, 32, 24, 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 430),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                    '러닝트립',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 30,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 2,
                      color: navy,
                    ),
                  ),
                  const SizedBox(height: 24),

                  // “코스 찾기” 버튼
                  SizedBox(
                    width: double.infinity,
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(999),
                      child: Material(
                        color: navy,
                        child: InkWell(
                          onTap: () {},
                          child: const Padding(
                            padding: EdgeInsets.symmetric(
                              horizontal: 24,
                              vertical: 16,
                            ),
                            child: Center(
                              child: Text(
                                '코스 찾기',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 17,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  // 로그인 / 회원가입 버튼
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        onPressed: () {
                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => const LoginPage(),
                            ),
                          );
                        },
                        child: const Text(
                          '로그인',
                          style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            color: navy,
                          ),
                        ),
                      ),
                      TextButton(
                        onPressed: () {
                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => const SignupPage(),
                            ),
                          );
                        },
                        child: const Text(
                          '회원가입',
                          style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            color: navy,
                          ),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 12),

                  // 선택된 도시 화면
                  Container(
                    width: double.infinity,
                    height: 360,
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(32),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withOpacity(0.04),
                          blurRadius: 24,
                          offset: const Offset(0, 12),
                        )
                      ],
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(32),
                      child: IndexedStack(
                        index: _selectedCityIndex,
                        children: cityPages,
                      ),
                    ),
                  ),

                  const SizedBox(height: 20),

                  // 도시 선택 칩
                  Row(
                    children: _cities.asMap().entries.map((entry) {
                      int index = entry.key;
                      String city = entry.value;
                      bool isSelected = _selectedCityIndex == index;

                      return Expanded(
                        child: Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 4),
                          child: GestureDetector(
                            onTap: () {
                              setState(() {
                                _selectedCityIndex = index;
                              });
                            },
                            child: AnimatedContainer(
                              duration: const Duration(milliseconds: 150),
                              padding: const EdgeInsets.symmetric(
                                vertical: 10,
                                horizontal: 4,
                              ),
                              decoration: BoxDecoration(
                                color: isSelected ? navy : Colors.white,
                                borderRadius: BorderRadius.circular(999),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.black.withOpacity(0.03),
                                    blurRadius: 10,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Center(
                                child: Text(
                                  city,
                                  style: TextStyle(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                    color: isSelected
                                        ? Colors.white
                                        : Colors.grey.shade800,
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                      );
                    }).toList(),
                  ),

                  const SizedBox(height: 12),
                ],
              ),
            ),
          ),
        ),
      ),

      // 하단 네비게이션 바
      bottomNavigationBar: Container(
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: const BorderRadius.only(
            topLeft: Radius.circular(28),
            topRight: Radius.circular(28),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.05),
              blurRadius: 18,
              offset: const Offset(0, -6),
            ),
          ],
        ),
        child: ClipRRect(
          borderRadius: const BorderRadius.only(
            topLeft: Radius.circular(28),
            topRight: Radius.circular(28),
          ),
          child: BottomNavigationBar(
            type: BottomNavigationBarType.fixed,
            currentIndex: _currentIndex,
            onTap: (index) => setState(() => _currentIndex = index),
            selectedFontSize: 11,
            unselectedFontSize: 11,
            backgroundColor: Colors.white,
            selectedItemColor: navy,
            unselectedItemColor: const Color(0xFF9CA3AF),
            items: const [
              BottomNavigationBarItem(
                icon: Icon(Icons.home_rounded),
                label: '홈',
              ),
              BottomNavigationBarItem(
                icon: Icon(Icons.place_rounded),
                label: '코스',
              ),
              BottomNavigationBarItem(
                icon: Icon(Icons.emoji_events_rounded),
                label: '챌린지',
              ),
              BottomNavigationBarItem(
                icon: Icon(Icons.person_rounded),
                label: '내 정보',
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ----------------------------------------------------
// 도시별 페이지 위젯
// ----------------------------------------------------
class CityPage extends StatelessWidget {
  final String city;

  const CityPage({super.key, required this.city});

  @override
  Widget build(BuildContext context) {
    // 도시별 이미지 맵핑
    final cityImages = {
      '서울': 'assets/seoul.png',
      '부산': 'assets/busan.png',
      '대구': 'assets/daegu.png',
      '제주': 'assets/jeju.png',
    };

    final imagePath = cityImages[city] ?? 'assets/seoul.png';

    return Stack(
      children: [
        // 도시별 이미지
        Positioned.fill(
          child: Image.asset(
            imagePath,
            fit: BoxFit.cover,
          ),
        ),

        // 도시 이름 라벨
        Positioned(
          bottom: 20,
          right: 20,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
            decoration: BoxDecoration(
              color: Colors.black.withOpacity(0.3),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              city,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 14,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ),
      ],
    );
  }
}

// ----------------------------------------------------
// 회원가입 페이지
// ----------------------------------------------------
class SignupPage extends StatefulWidget {
  const SignupPage({super.key});

  @override
  State<SignupPage> createState() => _SignupPageState();
}

class _SignupPageState extends State<SignupPage> {
  final _formKey = GlobalKey<FormState>();

  final _emailController = TextEditingController();
  final _nicknameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _fullNameController = TextEditingController();
  final _birthYearController = TextEditingController();

  String? _selectedGender;
  String? _selectedCity;
  String _selectedRunningLevel = 'BEGINNER';
  int? _selectedDistance;
  int? _selectedWeeklyGoal;

  bool _isLoading = false;

  // TODO: 실제 서버 주소로 변경 (예: http://192.168.0.10:5000)
  final String _baseUrl = 'http://127.0.0.1:5000';

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() => _isLoading = true);

    try {
      final res = await http.post(
        Uri.parse('$_baseUrl/signup'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': _emailController.text.trim(),
          'password': _passwordController.text,
          'nickname': _nicknameController.text.trim(),
          'full_name': _fullNameController.text.trim().isEmpty
              ? null
              : _fullNameController.text.trim(),
          'birth_year': _birthYearController.text.isEmpty
              ? null
              : int.tryParse(_birthYearController.text),
          'gender': _selectedGender,
          'city': _selectedCity,
          'running_level': _selectedRunningLevel,
          'preferred_distance_km': _selectedDistance,
          'weekly_goal_runs': _selectedWeeklyGoal,
        }),
      );

      final data = jsonDecode(res.body);

      if (res.statusCode == 201 && data['success'] == true) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('회원가입 완료!')),
        );
        Navigator.pop(context);
      } else {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(data['message'] ?? '회원가입 실패')),
        );
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('서버에 연결할 수 없습니다.')),
      );
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  void dispose() {
    _emailController.dispose();
    _nicknameController.dispose();
    _passwordController.dispose();
    _fullNameController.dispose();
    _birthYearController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    const navy = Color(0xFF102440);

    return Scaffold(
      appBar: AppBar(
        title: const Text('회원가입'),
        centerTitle: true,
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 430),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const SizedBox(height: 8),
                    const Text(
                      '러닝트립에 오신 것을 환영합니다 👟',
                      style: TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.w700,
                        color: navy,
                      ),
                    ),
                    const SizedBox(height: 24),

                    // 이메일
                    TextFormField(
                      controller: _emailController,
                      decoration: const InputDecoration(
                        labelText: '이메일 *',
                        border: OutlineInputBorder(),
                      ),
                      keyboardType: TextInputType.emailAddress,
                      validator: (value) {
                        if (value == null || value.trim().isEmpty) {
                          return '이메일을 입력해주세요.';
                        }
                        if (!value.contains('@')) {
                          return '이메일 형식이 올바르지 않습니다.';
                        }
                        return null;
                      },
                    ),
                    const SizedBox(height: 16),

                    // 닉네임
                    TextFormField(
                      controller: _nicknameController,
                      decoration: const InputDecoration(
                        labelText: '닉네임 *',
                        border: OutlineInputBorder(),
                      ),
                      validator: (value) {
                        if (value == null || value.trim().isEmpty) {
                          return '닉네임을 입력해주세요.';
                        }
                        return null;
                      },
                    ),
                    const SizedBox(height: 16),

                    // 비밀번호
                    TextFormField(
                      controller: _passwordController,
                      decoration: const InputDecoration(
                        labelText: '비밀번호 *',
                        border: OutlineInputBorder(),
                      ),
                      obscureText: true,
                      validator: (value) {
                        if (value == null || value.isEmpty) {
                          return '비밀번호를 입력해주세요.';
                        }
                        if (value.length < 6) {
                          return '비밀번호는 6자 이상이어야 합니다.';
                        }
                        return null;
                      },
                    ),
                    const SizedBox(height: 16),

                    // 이름 (선택)
                    TextFormField(
                      controller: _fullNameController,
                      decoration: const InputDecoration(
                        labelText: '이름 (선택)',
                        border: OutlineInputBorder(),
                      ),
                    ),
                    const SizedBox(height: 16),

                    // 출생연도 (선택)
                    TextFormField(
                      controller: _birthYearController,
                      decoration: const InputDecoration(
                        labelText: '출생연도 (예: 1998)',
                        border: OutlineInputBorder(),
                      ),
                      keyboardType: TextInputType.number,
                    ),
                    const SizedBox(height: 16),

                    // 성별 & 도시
                    Row(
                      children: [
                        Expanded(
                          child: DropdownButtonFormField<String>(
                            decoration: const InputDecoration(
                              labelText: '성별',
                              border: OutlineInputBorder(),
                            ),
                            value: _selectedGender,
                            items: const [
                              DropdownMenuItem(
                                  value: 'M', child: Text('남성')),
                              DropdownMenuItem(
                                  value: 'F', child: Text('여성')),
                              DropdownMenuItem(
                                  value: 'O', child: Text('기타/선택안함')),
                            ],
                            onChanged: (val) {
                              setState(() => _selectedGender = val);
                            },
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: DropdownButtonFormField<String>(
                            decoration: const InputDecoration(
                              labelText: '주 활동 도시',
                              border: OutlineInputBorder(),
                            ),
                            value: _selectedCity,
                            items: const [
                              DropdownMenuItem(
                                  value: '서울', child: Text('서울')),
                              DropdownMenuItem(
                                  value: '부산', child: Text('부산')),
                              DropdownMenuItem(
                                  value: '대구', child: Text('대구')),
                              DropdownMenuItem(
                                  value: '제주', child: Text('제주')),
                            ],
                            onChanged: (val) {
                              setState(() => _selectedCity = val);
                            },
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // 러닝 레벨
                    DropdownButtonFormField<String>(
                      decoration: const InputDecoration(
                        labelText: '러닝 레벨',
                        border: OutlineInputBorder(),
                      ),
                      value: _selectedRunningLevel,
                      items: const [
                        DropdownMenuItem(
                            value: 'BEGINNER', child: Text('입문자')),
                        DropdownMenuItem(
                            value: 'INTERMEDIATE', child: Text('중급자')),
                        DropdownMenuItem(
                            value: 'ADVANCED', child: Text('상급자')),
                      ],
                      onChanged: (val) {
                        if (val == null) return;
                        setState(() => _selectedRunningLevel = val);
                      },
                    ),
                    const SizedBox(height: 16),

                    // 선호 거리 & 주간 목표
                    Row(
                      children: [
                        Expanded(
                          child: DropdownButtonFormField<int>(
                            decoration: const InputDecoration(
                              labelText: '선호 거리 (km)',
                              border: OutlineInputBorder(),
                            ),
                            value: _selectedDistance,
                            items: const [
                              DropdownMenuItem(value: 5, child: Text('5km')),
                              DropdownMenuItem(value: 10, child: Text('10km')),
                              DropdownMenuItem(
                                  value: 21, child: Text('하프(21km)')),
                              DropdownMenuItem(
                                  value: 42, child: Text('풀(42km)')),
                            ],
                            onChanged: (val) {
                              setState(() => _selectedDistance = val);
                            },
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: DropdownButtonFormField<int>(
                            decoration: const InputDecoration(
                              labelText: '주당 목표 러닝 횟수',
                              border: OutlineInputBorder(),
                            ),
                            value: _selectedWeeklyGoal,
                            items: const [
                              DropdownMenuItem(value: 1, child: Text('1회')),
                              DropdownMenuItem(value: 2, child: Text('2회')),
                              DropdownMenuItem(value: 3, child: Text('3회')),
                              DropdownMenuItem(value: 4, child: Text('4회+')),
                            ],
                            onChanged: (val) {
                              setState(() => _selectedWeeklyGoal = val);
                            },
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 24),

                    SizedBox(
                      height: 48,
                      child: ElevatedButton(
                        onPressed: _isLoading ? null : _submit,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: navy,
                          foregroundColor: Colors.white,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(999),
                          ),
                        ),
                        child: _isLoading
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Colors.white,
                                ),
                              )
                            : const Text(
                                '회원가입',
                                style: TextStyle(
                                  fontSize: 16,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ----------------------------------------------------
// 로그인 페이지
// ----------------------------------------------------
class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _formKey = GlobalKey<FormState>();

  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();

  bool _isLoading = false;

  // TODO: 실제 서버 주소로 변경 (예: http://192.168.0.10:5000)
  final String _baseUrl = 'http://127.0.0.1:5000';

  String? _token; // 나중에 SharedPreferences 등으로 확장 가능

  Future<void> _login() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() => _isLoading = true);

    try {
      final res = await http.post(
        Uri.parse('$_baseUrl/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': _emailController.text.trim(),
          'password': _passwordController.text,
        }),
      );

      final data = jsonDecode(res.body);

      if (res.statusCode == 200 && data['success'] == true) {
        _token = data['token']; // 필요하면 어디에 저장해서 재사용

        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('로그인 성공!')),
        );

        Navigator.pop(context);
      } else {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(data['message'] ?? '로그인 실패')),
        );
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('서버에 연결할 수 없습니다.')),
      );
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    const navy = Color(0xFF102440);

    return Scaffold(
      appBar: AppBar(
        title: const Text('로그인'),
        centerTitle: true,
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 430),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const SizedBox(height: 8),
                    const Text(
                      '다시 만나서 반가워요 👋',
                      style: TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.w700,
                        color: navy,
                      ),
                    ),
                    const SizedBox(height: 24),

                    TextFormField(
                      controller: _emailController,
                      decoration: const InputDecoration(
                        labelText: '이메일',
                        border: OutlineInputBorder(),
                      ),
                      keyboardType: TextInputType.emailAddress,
                      validator: (value) {
                        if (value == null || value.trim().isEmpty) {
                          return '이메일을 입력해주세요.';
                        }
                        if (!value.contains('@')) {
                          return '이메일 형식이 올바르지 않습니다.';
                        }
                        return null;
                      },
                    ),
                    const SizedBox(height: 16),

                    TextFormField(
                      controller: _passwordController,
                      decoration: const InputDecoration(
                        labelText: '비밀번호',
                        border: OutlineInputBorder(),
                      ),
                      obscureText: true,
                      validator: (value) {
                        if (value == null || value.isEmpty) {
                          return '비밀번호를 입력해주세요.';
                        }
                        return null;
                      },
                    ),

                    const SizedBox(height: 24),

                    SizedBox(
                      height: 48,
                      child: ElevatedButton(
                        onPressed: _isLoading ? null : _login,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: navy,
                          foregroundColor: Colors.white,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(999),
                          ),
                        ),
                        child: _isLoading
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Colors.white,
                                ),
                              )
                            : const Text(
                                '로그인',
                                style: TextStyle(
                                  fontSize: 16,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
