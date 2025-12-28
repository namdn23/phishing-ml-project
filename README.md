import pandas as pd

# Input file là file đã lọc link chết
INPUT_FILE = 'urldata_clean.csv'
OUTPUT_FILE = 'urldata_balanced.csv'

def balance_data():
    print(f"⚖️ Đang cân bằng dữ liệu từ: {INPUT_FILE}")
    try:
        df = pd.read_csv(INPUT_FILE)
        
        # Tách 2 phe
        df_bad = df[df['label'] == 'bad']
        df_good = df[df['label'] == 'good']
        
        n_bad = len(df_bad)
        n_good = len(df_good)
        
        print(f"   🔴 Số lượng Bad gốc: {n_bad}")
        print(f"   🟢 Số lượng Good gốc: {n_good}")
        
        # --- CHIẾN THUẬT: UNDERSAMPLING (Cắt bớt Good) ---
        # Lấy số lượng Good bằng số lượng Bad (tỉ lệ 1:1)
        # Hoặc lấy gấp rưỡi (tỉ lệ 60:40) cho model học Good tốt hơn xíu
        target_good = int(n_bad * 1.2) # Lấy Good nhiều hơn Bad 20%
        
        if n_good > target_good:
            df_good_sampled = df_good.sample(n=target_good, random_state=42)
        else:
            df_good_sampled = df_good
            
        # Gộp lại
        df_balanced = pd.concat([df_bad, df_good_sampled])
        
        # Xáo trộn dữ liệu (Shuffle)
        df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print("-" * 30)
        print(f"✅ Đã cân bằng xong!")
        print(f"   🔴 Bad: {len(df_bad)}")
        print(f"   🟢 Good (Đã cắt): {len(df_good_sampled)}")
        print(f"   📊 Tổng cộng dataset mới: {len(df_balanced)}")
        
        # Lưu file
        df_balanced.to_csv(OUTPUT_FILE, index=False)
        print(f"💾 Đã lưu vào: {OUTPUT_FILE} (Dùng file này đi trích xuất feature!)")
        
    except Exception as e:
        print(f"❌ Lỗi: {e}")

if __name__ == "__main__":
    balance_data()
