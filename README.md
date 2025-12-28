import pandas as pd
import os

# --- CẤU HÌNH ---
# Đổi tên file này thành file bạn muốn check (ví dụ: urldata.csv hoặc urldata_clean.csv)
INPUT_FILE = 'urldata.csv' 

def check_data_balance():
    print(f"🚀 Đang phân tích file: {INPUT_FILE}...")
    
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Lỗi: Không tìm thấy file '{INPUT_FILE}'")
        return

    try:
        # Đọc file CSV
        df = pd.read_csv(INPUT_FILE)
        
        # 1. Kiểm tra tổng quan
        total_rows = len(df)
        print(f"📊 Tổng số dòng: {total_rows:,}")

        # 2. Đếm số lượng từng nhãn (bad/good)
        if 'label' in df.columns:
            counts = df['label'].value_counts()
            percentages = df['label'].value_counts(normalize=True) * 100
            
            print("\n--- KẾT QUẢ THỐNG KÊ ---")
            print(f"{'Label':<15} | {'Số lượng':<10} | {'Tỉ lệ %':<10}")
            print("-" * 45)
            
            for label, count in counts.items():
                percent = percentages[label]
                print(f"{str(label):<15} | {count:<10,} | {percent:.2f}%")
                
            print("-" * 45)
            
            # 3. Cảnh báo nếu dữ liệu bị lệch
            # Lấy số lượng của 2 nhãn phổ biến nhất
            if len(counts) >= 2:
                max_val = counts.values[0]
                min_val = counts.values[1]
                ratio = max_val / min_val
                
                if ratio > 3: # Nếu chênh lệch gấp 3 lần
                    print(f"\n⚠️ CẢNH BÁO: Dữ liệu đang bị MẤT CÂN BẰNG nghiêm trọng!")
                    print(f"   Nhãn '{counts.index[0]}' nhiều gấp {ratio:.1f} lần nhãn '{counts.index[1]}'.")
                    print(f"   -> Model sẽ học thiên vị nhãn nhiều hơn. Cần kiếm thêm dữ liệu cho nhãn ít.")
                else:
                    print(f"\n✅ Dữ liệu khá cân bằng (Tỉ lệ chênh lệch: {ratio:.1f}x). Tốt để train!")
        else:
            print("❌ Lỗi: Không tìm thấy cột 'label' trong file CSV.")

    except Exception as e:
        print(f"❌ Lỗi khi đọc file: {e}")

if __name__ == "__main__":
    check_data_balance()
