import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import base64
import threading
import asyncio
import time
import concurrent.futures
import os
from io import StringIO
from pyrogram import Client, filters
from pyrogram.types import Message, InlineKeyboardButton, InlineKeyboardMarkup
from pyromod import listen
from datetime import datetime
import re

# Global variables for tracking extraction status
extraction_active = False
current_extraction_id = None
current_status_message = None
progress_message = None
batch_name = ""

session = requests.Session()

# Define URLs and headers
base_url = 'https://online.utkarsh.com/'
login_url = 'https://online.utkarsh.com/web/Auth/login'
tiles_data_url = 'https://online.utkarsh.com/web/Course/tiles_data'
layer_two_data_url = 'https://online.utkarsh.com/web/Course/get_layer_two_data'
meta_source_url = '/meta_distributer/on_request_meta_source'

# Define function to handle errors
def handle_error(message, exception=None):
    print(f"Error: {message}")
    if exception:
        print(f"Exception details: {exception}")

# Configuration
API_URL = "https://application.utkarshapp.com/index.php/data_model"
COMMON_KEY = b"%!^F&^$)&^$&*$^&"
COMMON_IV = b"#*v$JvywJvyJDyvJ"
key_chars = "%!F*&^$)_*%3f&B+"
iv_chars = "#*$DJvyw2w%!_-$@"
HEADERS = {
    "Authorization": "Bearer 152#svf346t45ybrer34yredk76t",
    "Content-Type": "text/plain; charset=UTF-8",
    "devicetype": "1",
    "host": "application.utkarshapp.com",
    "lang": "1",
    "user-agent": "okhttp/4.9.0",
    "userid": "0",
    "version": "152"
}

# Encryption and Decryption Functions
def encrypt(data, use_common_key, key, iv):
    cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
    cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
    padded_data = pad(json.dumps(data, separators=(",", ":")).encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return b64encode(encrypted).decode() + ":"

def decrypt(data, use_common_key, key, iv):
    cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
    cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
    try:
        encrypted_data = b64decode(data.split(":")[0])
        decrypted_bytes = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_bytes, AES.block_size).decode()
        return decrypted
    except (ValueError, TypeError) as e:
        print(f"Decryption error: {e}")
        return None

def post_request(path, data=None, use_common_key=False, key=None, iv=None):
    encrypted_data = encrypt(data, use_common_key, key, iv) if data else data
    response = requests.post(f"{API_URL}{path}", headers=HEADERS, data=encrypted_data)
    decrypted_data = decrypt(response.text, use_common_key, key, iv)
    if decrypted_data:
        try:
            return json.loads(decrypted_data)
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
    return {}

def decrypt_stream(enc):
    try:
        enc = b64decode(enc)
        key = '%!$!%_$&!%F)&^!^'.encode('utf-8')
        iv = '#*y*#2yJ*#$wJv*v'.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_bytes = cipher.decrypt(enc)

        try:
            plaintext = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
        except Exception:
            plaintext = decrypted_bytes.decode('utf-8', errors='ignore')
        cleaned_json = ''
        for i in range(len(plaintext)):
            try:
                json.loads(plaintext[:i+1])
                cleaned_json = plaintext[:i+1]  
            except json.JSONDecodeError:
                continue
        final_brace_index = cleaned_json.rfind('}')
        if final_brace_index != -1:
            cleaned_json = cleaned_json[:final_brace_index + 1]

        return cleaned_json

    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def decrypt_and_load_json(enc):
    decrypted_data = decrypt_stream(enc)
    try:
        return json.loads(decrypted_data)
    except json.JSONDecodeError as e:
        print(f"JSON decoding error: {e}")
        return None

def encrypt_stream(plain_text):
    try:
        key = '%!$!%_$&!%F)&^!^'.encode('utf-8')
        iv = '#*y*#2yJ*#$wJv*v'.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)

        padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)

        return b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def sanitize_filename(name):
    return re.sub(r'[\\/*?:"<>|]', "_", name)

def process_video_item(video_item, fi, subject_name, key, iv):
    try:
        ji = video_item.get("id")
        jt = video_item.get("title")
        jti = video_item["payload"]["tile_id"]
        j4 = {
            "course_id": fi,
            "device_id": "server_does_not_validate_it",
            "device_name": "server_does_not_validate_it",
            "download_click": "0",
            "name": ji + "_0_0",
            "tile_id": jti,
            "type": "video"
        }
        j5 = post_request(meta_source_url, j4, key=key, iv=iv)
        cj = j5.get("data", {})
        if cj:
            qo = cj.get("bitrate_urls", [])
            if qo and isinstance(qo, list):
                for index in [3, 2, 1, 0]:
                    if len(qo) > index:
                        selected_vu = qo[index].get("url", "")
                        if selected_vu:
                            pu = selected_vu.split("?Expires=")[0]
                            return {
                                "subject": subject_name,
                                "title": jt,
                                "url": pu,
                                "type": "video"
                            }
            else:
                vu = cj.get("link", "")
                if vu:
                    if ".m3u8" in vu or ".pdf" in vu:
                        pu = vu.split("?Expires=")[0]
                        file_type = "pdf" if ".pdf" in vu else "video"
                    elif ".ws" in vu and "https" in vu:
                        pu = vu
                        file_type = "video"
                    else:
                        pu = f"https://www.youtube.com/embed/{vu}"
                        file_type = "youtube"
                    return {
                        "subject": subject_name,
                        "title": jt,
                        "url": pu,
                        "type": file_type
                    }
    except Exception as e:
        print(f"⚠️ Video error: {video_item.get('title')} - {e}")
    return None

async def update_progress(client, message, course_name, subject_name, topic_name, video_count, doc_count):
    global progress_message
    
    progress_text = f"""
🎬 **Utkarsh Batch Extractor** 🎬

**📦 Batch:** {course_name}
**📘 Subject:** {subject_name}
**📖 Topic:** {topic_name}

**📊 Progress:**
🎥 Videos: {video_count}
📄 PDFs: {doc_count}

⏰ {datetime.now().strftime('%d-%m-%Y  %H:%M:%S')}

🔄 Extraction in progress...
"""
    
    try:
        if progress_message:
            await progress_message.edit_text(progress_text)
        else:
            progress_message = await message.reply(progress_text)
    except Exception as e:
        print(f"Error updating progress: {e}")

async def utk(course_id, client, message):
    global extraction_active, current_extraction_id, batch_name, progress_message
    
    if extraction_active:
        return "❌ Another extraction is already in progress. Please wait for it to complete."
    
    extraction_active = True
    current_extraction_id = course_id
    progress_message = None
    
    try:
        # Create a clean output directory
        output_dir = "Utkarsh_Extracts"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        output_file = os.path.join(output_dir, f"Utkarsh_Batch_{course_id}.txt")
        if os.path.exists(output_file):
            os.remove(output_file)
            
        r1 = session.get(base_url)
        csrf_token = r1.cookies.get('csrf_name')
        if not csrf_token:
            raise ValueError("CSRF token not found.")
    except Exception as e:
        handle_error("Failed to retrieve CSRF token", e)
        extraction_active = False
        current_extraction_id = None
        return f"❌ Failed to retrieve CSRF token: {e}"

    # Step 2: Login
    email = "9571484459"
    password = "kajukaju"
    d1 = {
        'csrf_name': csrf_token,
        'mobile': email,
        'url': '0',
        'password': password,
        'submit': 'LogIn',
        'device_token': 'null'
    }

    h = {
        'Host': 'online.utkarsh.com',
        'Sec-Ch-Ua': '"Chromium";v="119", "Not?A_Brand";v="24"',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Sec-Ch-Ua-Mobile': '?0',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.199 Safari/537.36'
    }

    try:
        u2 = session.post(login_url, data=d1, headers=h).json()
        r2 = u2.get("response")
        dr1 = decrypt_and_load_json(r2)
        token = dr1.get("token")
        jwt = dr1.get("data", {}).get("jwt")

        h["token"] = token
        h["jwt"] = jwt
        HEADERS["jwt"] = jwt
    except Exception as e:
        handle_error("Failed to log in or retrieve tokens", e)
        extraction_active = False
        current_extraction_id = None
        return f"❌ Failed to log in or retrieve tokens: {e}"

    # Step 3: Retrieve User Profile
    try:
        profile = post_request("/users/get_my_profile", use_common_key=True)
        user_id = profile["data"]["id"]
        HEADERS["userid"] = user_id

        key = "".join(key_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
        iv = "".join(iv_chars[int(i)] for i in (user_id + "1524567456436545")[:16]).encode()
    except Exception as e:
        handle_error("Failed to retrieve user profile", e)
        extraction_active = False
        current_extraction_id = None
        return f"❌ Failed to retrieve user profile: {e}"

    # Step 4: Input course ID
    
    d3 = {
        "course_id": course_id,
        "revert_api": "1#0#0#1",
        "parent_id": 0,
        "tile_id": "15330",
        "layer": 1,
        "type": "course_combo"
    }

    # Step 5: Encrypt and send course tile request
    try:
        encrypted = encrypt_stream(json.dumps(d3))
        d4 = {'tile_input': encrypted, 'csrf_name': csrf_token}
        u4 = session.post(tiles_data_url, headers=h, data=d4).json()
        r4 = u4.get("response")
        dr3 = decrypt_and_load_json(r4)
    except Exception as e:
        handle_error("Failed to retrieve course data", e)
        extraction_active = False
        current_extraction_id = None
        return f"❌ Failed to retrieve course data: {e}"

    # Step 6: Extract Subject Info (Layer 1)
    start = time.time()
    
    # Counters for progress
    video_count = 0
    doc_count = 0
    
    # 🔁 Start main scraping
    for course in dr3.get("data", []):
        try:
            if not extraction_active:  # Check if extraction was stopped
                break
                
            fi = course.get("id")
            tn = course.get("title")
            batch_name = tn  # Set the global batch name
            binfo = course.get("segment_information")
            print(f"📚 {fi} - {tn}\n{binfo}")

            # Create a structured output
            output_content = []
            output_content.append("╔══════════════════════════════════════════════╗")
            output_content.append(f"║            UTKARSH BATCH EXTRACTOR           ║")
            output_content.append("╠══════════════════════════════════════════════╣")
            output_content.append(f"║ 📦 Batch: {tn:<35} ║")
            output_content.append(f"║ 📊 Content: {binfo:<33} ║")
            output_content.append(f"║ ⏰ Date: {datetime.now().strftime('%d-%m-%Y %H:%M:%S'):<30} ║")
            output_content.append("╚══════════════════════════════════════════════╝")
            output_content.append("")

            # Layer 1
            d5 = {"course_id": fi, "layer": 1, "page": 1, "parent_id": fi, "revert_api": "1#1#0#1", "tile_id": "0", "type": "content"}
            d6 = {'tile_input': encrypt_stream(json.dumps(d5)), 'csrf_name': csrf_token}
            dr4 = decrypt_and_load_json(session.post(tiles_data_url, headers=h, data=d6).json()["response"])

            for subj in dr4["data"]["list"]:
                if not extraction_active:  # Check if extraction was stopped
                    break
                    
                sfi = subj.get("id")
                sfn = subj.get("title").strip().replace("\n", " ")
                print(f"📘 Subject: {sfn}")

                # Add subject header to output
                output_content.append("")
                output_content.append("▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄")
                output_content.append(f"📘 SUBJECT: {sfn}")
                output_content.append("▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀")
                output_content.append("")

                # Layer 2
                d7 = {"course_id": fi, "parent_id": fi, "layer": 2, "page": 1, "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, "topic_id": sfi, "type": "content"}
                d8 = {'layer_two_input_data': base64.b64encode(json.dumps(d7).encode()).decode(), 'csrf_name': csrf_token}
                dr5 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d8).json()["response"])

                for topic in dr5["data"]["list"]:
                    if not extraction_active:  # Check if extraction was stopped
                        break
                        
                    ti = topic.get("id")
                    tt = topic.get("title")

                    # Update progress
                    await update_progress(client, message, tn, sfn, tt, video_count, doc_count)

                    # Add topic header to output
                    output_content.append("")
                    output_content.append(f"  📖 TOPIC: {tt}")
                    output_content.append("  ──────────────────────────────────────────")

                    # Layer 3
                    d9 = {"course_id": fi, "parent_id": fi, "layer": 3, "page": 1, "revert_api": "1#0#0#1", "subject_id": sfi, "tile_id": 0, "topic_id": ti, "type": "content"}
                    d10 = {'layer_two_input_data': base64.b64encode(json.dumps(d9).encode()).decode(), 'csrf_name': csrf_token}
                    dr6 = decrypt_and_load_json(session.post(layer_two_data_url, headers=h, data=d10).json()["response"])

                    if "data" in dr6 and "list" in dr6["data"]:
                        video_items = dr6["data"]["list"]
                        with ThreadPoolExecutor(max_workers=200) as executor:
                            futures = [
                                executor.submit(process_video_item, v, fi, sfn, key, iv)
                                for v in video_items
                            ]
                            for future in as_completed(futures):
                                if not extraction_active:  # Check if extraction was stopped
                                    break
                                    
                                result = future.result()
                                if result:
                                    # Update counters
                                    if result["type"] == "video" or result["type"] == "youtube":
                                        video_count += 1
                                    else:
                                        doc_count += 1
                                    
                                    # Add to output with proper formatting
                                    icon = "🎥" if result["type"] in ["video", "youtube"] else "📄"
                                    output_content.append(f"  {icon} {result['title']}")
                                    output_content.append(f"     🔗 {result['url']}")
                                    output_content.append("")

            # 💾 Final write to file
            with open(output_file, "w", encoding='utf-8') as f:
                f.write("\n".join(output_content))

        except Exception as e:
            print(f"❌ Error in course {fi}: {e}")

    end = time.time()
    extraction_active = False
    current_extraction_id = None
    
    if progress_message:
        try:
            await progress_message.delete()
        except:
            pass
    
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        # Add summary to the beginning of the file
        with open(output_file, 'r+', encoding='utf-8') as f:
            content = f.read()
            f.seek(0, 0)
            
            summary = f"""
╔══════════════════════════════════════════════╗
║            EXTRACTION COMPLETED              ║
╠══════════════════════════════════════════════╣
║ 📦 Batch: {batch_name:<35} ║
║ 🎬 Videos: {video_count:<38} ║
║ 📁 PDFs: {doc_count:<40} ║
║ ⏰ Time: {end - start:.2f} seconds{"":<24} ║
║ 📅 Date: {datetime.now().strftime('%d-%m-%Y %H:%M:%S'):<30} ║
╚══════════════════════════════════════════════╝

"""
            f.write(summary + content)
        
        print(f"\n⏱️ Total Extraction Completed in {end - start:.2f} seconds.")
        print(f"📁 Output saved to: {output_file}")
        return output_file
    else:
        print("❌ Extraction failed. No output file was created.")
        return None

# Bot configuration
API_ID = 24250238  # 🔑 Replace with your API ID
API_HASH = "cb3f118ce5553dc140127647edcf3720"  # 🔑 Replace with your API HASH
BOT_TOKEN = "6234022831:AAGXxnk_pOGRm0dUAFPQHjgF9h2vEtdzGTs"  # 🤖 Replace with your bot token
ALLOWED_USER = 6175650047  # your Telegram user ID

bot = Client("utkarqwesh_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

@bot.on_message(filters.command("start") & filters.user(ALLOWED_USER))
async def start_handler(client: Client, message: Message):
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Start Extraction", callback_data="start_extraction")],
        [InlineKeyboardButton("⏹️ Stop Extraction", callback_data="stop_extraction")],
        [InlineKeyboardButton("🔄 Restart Bot", callback_data="restart_bot")]
    ])
    
    await message.reply(
        "👋 Welcome to the Utkarsh Extractor Bot!\n\n"
        "Use /utkarsh to begin extracting a course by batch ID.\n"
        "Made by x",
        reply_markup=keyboard
    )

@bot.on_callback_query(filters.user(ALLOWED_USER))
async def handle_callback(client, callback_query):
    global extraction_active, current_extraction_id
    
    data = callback_query.data
    await callback_query.answer()
    
    if data == "start_extraction":
        if extraction_active:
            await callback_query.message.edit("❌ Extraction is already in progress.")
        else:
            await callback_query.message.edit("🔄 Starting extraction process...")
            await get_course_id(client, callback_query.message)
            
    elif data == "stop_extraction":
        if extraction_active:
            extraction_active = False
            await callback_query.message.edit(f"⏹️ Extraction stopped for course ID: {current_extraction_id}")
        else:
            await callback_query.message.edit("ℹ️ No extraction is currently in progress.")
            
    elif data == "restart_bot":
        await callback_query.message.edit("🔄 Restarting bot...")
        os.execl(sys.executable, sys.executable, *sys.argv)

# === /utkarsh command ===
@bot.on_message(filters.command("utkarsh") & filters.user(ALLOWED_USER))
async def get_course_id(client: Client, message: Message):
    try:
        # Step 1: Ask for Batch ID
        ask = await message.reply("👋 Hey I Am x\n\n📥 Please send the *Batch ID* to extract:")

        # Step 2: Wait for response
        response = await bot.listen(message.chat.id, timeout=120)
        course_id = response.text.strip()

        # Step 3: Acknowledge
        status_msg = await message.reply("⚙️ Starting extraction... Please wait.")
        
        # Step 4: Run your main logic
        result = await utk(course_id, client, message)  # 🔁 Your own function that extracts course
        
        # Step 5: Send result
        if result:
            # Read the file content to get the summary
            with open(result, 'r', encoding='utf-8') as f:
                content = f.read()
                # Extract the summary from the first few lines
                summary_lines = content.split('\n')[:12]
                summary = '\n'.join(summary_lines)
            
            await message.reply(f"✅ Extraction completed!\n\n{summary}")
            await message.reply_document(result, caption=f"📦 Complete batch extraction for ID: {course_id}")
            os.remove(result)
        else:
            await message.reply("❌ Extraction failed. No content was found.")
            
    except asyncio.TimeoutError:
        await message.reply("❌ Timeout. Please try again.")
    except Exception as e:
        await message.reply(f"❌ Error: {e}")

# === Start the Bot ===
if __name__ == "__main__":
    print("🤖 Bot is starting...")
    bot.run()