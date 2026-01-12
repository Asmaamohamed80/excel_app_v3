import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime
import io

# --- Configuration ---
st.set_page_config(page_title="Smart Excel System V3", layout="wide")

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('system_v3.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notifications 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, message TEXT, timestamp DATETIME)''')
    
    c.execute("SELECT count(*) FROM users")
    if c.fetchone()[0] == 0:
        admin_pw = hashlib.sha256("admin123".encode()).hexdigest()
        user_pw = hashlib.sha256("user123".encode()).hexdigest()
        c.execute("INSERT INTO users VALUES (?, ?, ?)", ("admin", admin_pw, "Admin"))
        c.execute("INSERT INTO users VALUES (?, ?, ?)", ("user", user_pw, "Viewer"))
    conn.commit()
    conn.close()

def add_notification(user, message):
    try:
        conn = sqlite3.connect('system_v3.db')
        c = conn.cursor()
        c.execute("INSERT INTO notifications (user, message, timestamp) VALUES (?, ?, ?)", 
                  (user, message, datetime.now()))
        conn.commit()
        conn.close()
    except:
        pass

def get_notifications(user):
    try:
        conn = sqlite3.connect('system_v3.db')
        df = pd.read_sql_query("SELECT message, timestamp FROM notifications WHERE user = ? ORDER BY timestamp DESC", conn, params=(user,))
        conn.close()
        return df
    except:
        return pd.DataFrame(columns=['message', 'timestamp'])

# --- Authentication ---
def login():
    st.sidebar.title("🔐 Login")
    username = st.sidebar.text_input("Username", key="login_user")
    password = st.sidebar.text_input("Password", type="password", key="login_pass")
    if st.sidebar.button("Login"):
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect('system_v3.db')
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, hashed_pw))
        result = c.fetchone()
        conn.close()
        if result:
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            st.session_state['role'] = result[0]
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials")

# --- Main App ---
def main():
    init_db()
    
    # Initialize session states for data persistence
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    if 'main_df' not in st.session_state:
        st.session_state['main_df'] = None

    if not st.session_state['logged_in']:
        st.title("🚀 Smart Excel System (V3 - Persistent)")
        st.info("Login: admin / admin123")
        login()
        return

    # Sidebar
    st.sidebar.title(f"👤 {st.session_state['username']}")
    st.sidebar.write(f"Role: **{st.session_state['role']}**")
    page = st.sidebar.radio("Menu", ["Dashboard", "Excel Editor", "Notifications"])
    
    if st.sidebar.button("Logout"):
        st.session_state['logged_in'] = False
        st.session_state['main_df'] = None # Clear data on logout for security
        st.rerun()

    if page == "Dashboard":
        st.title("📊 Dashboard")
        st.success(f"Welcome, {st.session_state['username']}!")
        if st.session_state['main_df'] is not None:
            st.info(f"✅ There is a file currently loaded with {len(st.session_state['main_df'])} rows.")
        else:
            st.warning("ℹ️ No file loaded yet. Go to 'Excel Editor' to upload one.")

    elif page == "Excel Editor":
        st.title("📝 Excel Editor")
        
        # Only show uploader if no data is loaded, or provide a reset button
        if st.session_state['main_df'] is None:
            file = st.file_uploader("Upload CSV or Excel", type=['csv', 'xlsx'])
            if file:
                if file.name.endswith('.csv'):
                    st.session_state['main_df'] = pd.read_csv(file)
                else:
                    st.session_state['main_df'] = pd.read_excel(file, engine='openpyxl')
                st.rerun()
        else:
            if st.button("🗑️ Clear and Upload New File"):
                st.session_state['main_df'] = None
                st.rerun()

            df = st.session_state['main_df']
            is_admin = st.session_state['role'] == "Admin"
            
            st.subheader("Interactive Grid")
            if not is_admin:
                st.warning("⚠️ View-Only Mode")
            
            # The key here is to update session_state directly
            edited_df = st.data_editor(
                df,
                use_container_width=True,
                num_rows="dynamic" if is_admin else "fixed",
                disabled=not is_admin,
                key="data_editor_v3"
            )

            # Update the main dataframe in session state whenever edited
            if is_admin:
                if st.button("💾 Save All Changes"):
                    st.session_state['main_df'] = edited_df
                    add_notification(st.session_state['username'], f"Saved changes to the dataset ({len(edited_df)} rows).")
                    st.success("All changes saved successfully and will persist during your session!")

            # Export
            csv = edited_df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Updated File (CSV)", csv, "updated_data.csv", "text/csv")

    elif page == "Notifications":
        st.title("🔔 Notifications History")
        notifs = get_notifications(st.session_state['username'])
        if not notifs.empty:
            for _, row in notifs.iterrows():
                st.info(f"**{row['timestamp']}**: {row['message']}")
        else:
            st.write("No notifications yet.")

if __name__ == "__main__":
    main()
