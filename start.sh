#!/usr/bin/env bash
# SecureLogin 한 번에 실행 스크립트
#   처음: 필요한 프로그램 설치 → 실행 환경 만들기 → DB·계정 만들기 → 서버 실행
#   그다음부터: 바로 서버 실행
set -e
cd "$(dirname "$0")"

echo "== SecureLogin 시작 =="

# 1) 파이썬·venv 준비 (없을 때만 설치)
if ! python3 -c "import venv, ensurepip" >/dev/null 2>&1; then
  echo "▶ python3-venv 설치 (비밀번호를 물으면 리눅스 사용자 비밀번호 입력)"
  sudo apt update
  sudo apt install -y python3 python3-venv
fi

# 2) 실행 환경 (처음 한 번)
if [ ! -d venv ]; then
  echo "▶ 실행 환경 만드는 중..."
  python3 -m venv venv
  ./venv/bin/pip install -q -r requirements.txt
fi

# 3) DB·관리자 계정 (처음 한 번)
if [ ! -f securelogin.db ]; then
  echo "▶ 관리자(admin) 비밀번호를 정해 주세요 (8자 이상, 입력해도 화면에 안 보이는 게 정상)"
  ./venv/bin/python app.py init
fi

# 4) 방화벽이 켜져 있으면 8080 열기
if command -v ufw >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo ufw status | grep -q "Status: active" && sudo ufw allow 8080/tcp >/dev/null || true
fi

# 5) 접속 주소 안내
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "✔ 이 VM에서 열기     : http://localhost:8080/login"
[ -n "$IP" ] && echo "✔ 다른 컴퓨터에서 열기: http://$IP:8080/login"
echo "✔ 관리자 대시보드    : admin으로 로그인 → /admin"
echo "  (끄려면 Ctrl + C)"
echo ""

./venv/bin/python app.py run
