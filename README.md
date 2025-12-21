import pandas as pd

# 1. Đọc file (thêm low_memory=False để tránh cảnh báo)
df = pd.read_csv('PhiUSIIL_Final_Dataset_Clean.csv', low_memory=False)

# 2. ÉP KIỂU dữ liệu cột V10 về dạng số (Rất quan trọng)
# errors='coerce' sẽ biến các ô lỗi hoặc trống thành NaN
df['V10_HTTP_Extraction_Success'] = pd.to_numeric(df['V10_HTTP_Extraction_Success'], errors='coerce')

# 3. Lọc lại: Chỉ lấy những dòng bằng 1
# Dùng .dropna() để loại bỏ các dòng bị lỗi kiểu dữ liệu ở bước trên
df_clean = df[df['V10_HTTP_Extraction_Success'] == 1].dropna(subset=['V10_HTTP_Extraction_Success']).copy()

# 4. Kiểm tra lại số lượng
print(f"✅ Đã lọc xong! Còn lại {len(df_clean)} mẫu chất lượng cao.")

if len(df_clean) > 0:
    print(f"📊 Phân bố nhãn mới:\n{df_clean['label'].value_counts()}")
    # Lưu ra file sạch để dùng cho Train AI
    df_clean.to_csv('Dataset_Ready_to_Train.csv', index=False)
else:
    print("❌ Vẫn chưa tìm thấy mẫu nào. Hãy kiểm tra lại file bằng lệnh df.info()")
