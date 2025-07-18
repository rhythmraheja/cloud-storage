import streamlit as st
import sqlite3
import boto3
from botocore.exceptions import NoCredentialsError
import hashlib
import os
from botocore.client import Config

# ---------- CONFIGURE AWS S3 ----------
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
BUCKET_NAME = os.getenv("BUCKET_NAME")

s3 = boto3.client(
    "s3",
    region_name="eu-north-1",  # Use your bucket's region
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    config=Config(signature_version='s3v4')
)

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect("file_manager.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            filename TEXT,
            category TEXT,
            s3_url TEXT
        )
    ''')
    conn.commit()
    return conn, c

conn, c = init_db()

# ---------- UTILITY FUNCTIONS ----------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def upload_to_s3(file_obj, file_name):
    try:
        s3.upload_fileobj(file_obj, BUCKET_NAME, file_name)
        return file_name  # Save only S3 key
    except NoCredentialsError:
        st.error("AWS credentials not valid.")
        return None

def generate_presigned_url(file_key):
    try:
        return s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET_NAME, 'Key': file_key},
            ExpiresIn=3600
        )
    except Exception as e:
        st.error(f"Error generating download link: {e}")
        return "#"

def categorize_file(file_name):
    if file_name.endswith(('.jpg', '.jpeg', '.png', '.gif')):
        return 'Images'
    elif file_name.endswith(('.pdf', '.docx', '.txt', '.pptx')):
        return 'Documents'
    else:
        return 'Others'

# ---------- SIGNUP ----------
def signup():
    st.subheader("🔐 Sign Up")
    email = st.text_input("Email")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")
    if st.button("Create Account"):
        if password != confirm:
            st.error("Passwords do not match.")
        else:
            hashed_pw = hash_password(password)
            try:
                c.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed_pw))
                conn.commit()
                st.success("Account created. Please log in.")
            except sqlite3.IntegrityError:
                st.error("Email already registered.")

# ---------- LOGIN ----------
def login():
    st.subheader("🔓 Log In")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        c.execute("SELECT username, password FROM users WHERE email = ?", (email,))
        result = c.fetchone()
        if result and verify_password(password, result[1]):
            st.session_state.logged_in = True
            st.session_state.email = email
            st.session_state.username = result[0]
            st.success(f"Welcome, {st.session_state.username}!")
        else:
            st.error("Invalid credentials.")

# ---------- LOGOUT ----------
def logout():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.email = ""

# ---------- MAIN DASHBOARD ----------
def dashboard():
    st.title("📁 CloudEase File Manager")
    st.markdown(f"Welcome **{st.session_state.username}** ({st.session_state.email})! 🎉")
    st.divider()

    # 📤 Upload Section
    with st.expander("📤 Upload a New File"):
        uploaded_file = st.file_uploader("Choose a file to upload")
        if uploaded_file:
            category = categorize_file(uploaded_file.name)
            s3_key = upload_to_s3(uploaded_file, uploaded_file.name)
            if s3_key:
                c.execute("INSERT INTO files (email, filename, category, s3_url) VALUES (?, ?, ?, ?)",
                          (st.session_state.email, uploaded_file.name, category, s3_key))
                conn.commit()
                st.success(f"✅ Uploaded: {uploaded_file.name}")

    st.divider()

    # 🔍 Search Section
    with st.expander("🔍 Search Your Files"):
        query = st.text_input("Enter filename to search")
        if query:
            c.execute("SELECT filename, category, s3_url FROM files WHERE email=? AND filename LIKE ?", 
                      (st.session_state.email, f"%{query}%"))
            results = c.fetchall()
            if results:
                for r in results:
                    st.write(f"📄 **{r[0]}** | 🗂️ {r[1]}")
                    download_url = generate_presigned_url(r[2])
                    st.markdown(f"[📥 Download File]({download_url})", unsafe_allow_html=True)
            else:
                st.warning("No matching files found.")

    st.divider()

    # 📂 View All Files
    with st.expander("📂 View All My Files"):
        c.execute("SELECT filename, category, s3_url FROM files WHERE email=?", (st.session_state.email,))
        files = c.fetchall()
        seen = set()
        for f in files:
            if f[0] not in seen:
                seen.add(f[0])
                st.write(f"📄 **{f[0]}** | 🗂️ {f[1]}")
                download_url = generate_presigned_url(f[2])
                st.markdown(f"[📥 Download File]({download_url})", unsafe_allow_html=True)
        if not seen:
            st.info("No files uploaded yet.")

    st.divider()

    # 🤝 Share File
    with st.expander("🤝 Share a File"):
        c.execute("SELECT filename, category, s3_url FROM files WHERE email=?", (st.session_state.email,))
        my_files = c.fetchall()
        if my_files:
            selected_file = st.selectbox("Select file to share", my_files, format_func=lambda x: f"{x[0]} ({x[1]})")
            recipient_email = st.text_input("Recipient's Email")

            if st.button("🔗 Share File"):
                if recipient_email and selected_file:
                    c.execute("INSERT INTO shared_files (sender_email, receiver_email, filename, s3_url, category) VALUES (?, ?, ?, ?, ?)",
                              (st.session_state.email, recipient_email, selected_file[0], selected_file[2], selected_file[1]))
                    conn.commit()
                    st.success(f"📨 Shared '{selected_file[0]}' with {recipient_email}")
                else:
                    st.warning("Select a file and enter a valid email.")

    st.divider()

    # 📬 Shared With Me
    with st.expander("📬 Files Shared With Me"):
        c.execute("SELECT sender_email, filename, category, s3_url FROM shared_files WHERE receiver_email=?", (st.session_state.email,))
        shared_files = c.fetchall()
        if shared_files:
            for s in shared_files:
                st.write(f"📄 **{s[1]}** | 🗂️ {s[2]} | 👤 From: {s[0]}")
                shared_url = generate_presigned_url(s[3])
                st.markdown(f"[📥 Download File]({shared_url})", unsafe_allow_html=True)
        else:
            st.info("No files shared with you.")

    st.divider()

    # 🔧 Delete & Logout
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🗑️ Delete All My Files"):
            c.execute("DELETE FROM files WHERE email=?", (st.session_state.email,))
            conn.commit()
            st.success("All files deleted.")

    with col2:
        if st.button("🚪 Logout"):
            logout()
            st.rerun()




# ---------- MAIN ----------
def main():
    st.set_page_config("CloudEase File Manager", "📁")
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if st.session_state.logged_in:
        dashboard()
    else:
        st.title("☁️ CloudEase File Manager")  # Show title on landing/login/signup
        opt = st.radio("Choose an option", ["Login", "Sign Up"])
        if opt == "Login":
            login()
        else:
            signup()

if __name__ == "__main__":
    main()
