# Phish-check API (Heuristics)

API ขนาดเล็กด้วย Node.js + Express สำหรับตรวจ URL แบบ heuristics (พื้นฐาน) เพื่อช่วยคัดกรองกรณี phishing.

หมายเหตุ: เป็นการตรวจแบบ heuristics เท่านั้น ไม่ใช่การตรวจสอบที่แม่นยำ 100% หากต้องการรวม Google Safe Browsing หรือ PhishTank ต้องใส่ API key และขอเพิ่มฟีเจอร์ได้

การติดตั้ง

1. ติดตั้ง Node.js (แนะนำ >=14)
2. ในโฟลเดอร์นี้รัน:

   npm install

3. เริ่มเซิร์ฟเวอร์:

   npm start

โดยค่าเริ่มต้นเซิร์ฟเวอร์จะรันที่พอร์ต 3000

การใช้งาน

POST /check
Content-Type: application/json
{
  "url": "http://example.com/login"
}

ตัวอย่าง curl:

curl -s -X POST -H "Content-Type: application/json" -d '{"url":"http://example.com/login"}' http://localhost:3000/check | jq

ผลลัพธ์ตัวอย่าง:
{
  "ok": true,
  "input": "http://example.com/login",
  "normalized": "http://example.com/login",
  "hostname": "example.com",
  "verdict": "clean",
  "score": 0,
  "details": [ ... ]
}

ต้องการให้เพิ่มการตรวจแบบอื่น (Google Safe Browsing / PhishTank / WHOIS) บอกได้เลย จะต่อให้.
