from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
from datetime import datetime
import bcrypt
import datetime
import locale

# ----------------------------------------------------------------
#  تكوين التطبيق
# ----------------------------------------------------------------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # استخدم مفتاحًا سريًا حقيقيًا في الإنتاج

# ----------------------------------------------------------------
#  دوال التعامل مع قاعدة البيانات
# ----------------------------------------------------------------

def get_db():
    """
    تعيد دالة الاتصال بقاعدة البيانات SQLite.
    ملاحظة: يمكن إغلاق الاتصال لاحقًا إذا لزم الأمر.
    """
    conn = sqlite3.connect("aidlink.db")
    conn.row_factory = sqlite3.Row  # يتيح الوصول إلى البيانات باستخدام أسماء الأعمدة
    return conn

def init_db():
    """
    إنشاء الجداول في قاعدة البيانات إذا لم تكن موجودة مسبقًا.
    """
    conn = get_db()
    cursor = conn.cursor()

    # جدول المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT,
            orgname TEXT
        )
    ''')

    # جدول المستفيدين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS beneficiaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            national_id TEXT NOT NULL UNIQUE,
            contact_number TEXT,
            address TEXT,
            family_members INTEGER,
            org TEXT
        )
    ''')

    # جدول الموارد
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resource_name TEXT NOT NULL,
            doner TEXT,
            quantity INTEGER NOT NULL,
            org TEXT
        )
    ''')

    # جدول توزيع الموارد
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resources_DE (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            national_id TEXT NOT NULL,
            resource_name TEXT NOT NULL,
            resource_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            date TEXT,
            org TEXT
        )
    ''')

    conn.commit()
    conn.close()

# ----------------------------------------------------------------
#  دوال المساعدة والتحقق من تسجيل الدخول
# ----------------------------------------------------------------

def is_logged_in():
    """
    تتحقق مما إذا كان المستخدم مسجلاً للدخول.
    """
    return session.get('user_id') is not None

def login_required(f):
    """
    Decorator للتحقق من تسجيل الدخول قبل الوصول إلى المسار المطلوب.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------
#  المسارات (Routes)
# ----------------------------------------------------------------

@app.route("/")
def index():
    """
    الصفحة الرئيسية، تُحوِّل تلقائيًا إلى تسجيل الدخول أو لوحة التحكم.
    """
    if not is_logged_in():
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

# المسار لصفحة "بحث مستفيدين"
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_beneficiaries():
    conn = get_db()
    cursor = conn.cursor()
    role = session.get("role")

    # Ensure only 'ادارة' role has access
    if role != 'ادارة':
        return "Access Denied", 403

    beneficiaries = []
    if request.method == 'POST':
        search_term = request.form.get('search_term', '').strip()

        # Safely execute the query with parameterized input
        cursor.execute(
            "SELECT * FROM beneficiaries WHERE name LIKE ? OR national_id = ? ORDER BY name ASC",
            (f"%{search_term}%", search_term)
        )
        beneficiaries = cursor.fetchall()

    return render_template('search_beneficiaries.html', beneficiaries=beneficiaries)




@app.route('/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    conn = get_db()
    cursor = conn.cursor()
    role = session.get("role")

    # تحقق من أن المستخدم لديه صلاحيات "إدارة"
    if role != 'ادارة':
        return "Access Denied", 403

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        if action == 'delete':
            # حذف المستخدم
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        elif action == 'edit':
            # تعديل بيانات المستخدم
            new_username = request.form.get('username')
            new_role = request.form.get('role')
            new_orgname = request.form.get('orgname')
            cursor.execute(
                "UPDATE users SET username = ?, role = ?, orgname = ? WHERE id = ?",
                (new_username, new_role, new_orgname, user_id)
            )
            conn.commit()
        elif action == 'update_password':
            # تحديث كلمة المرور
            new_password = request.form.get('password')
            hashed_password = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hashed_password, user_id)
            )
            conn.commit()

    # جلب قائمة المستخدمين لعرضها في الواجهة
    cursor.execute("SELECT id, username, role, orgname FROM users ORDER BY role ASC")
    users = cursor.fetchall()

    return render_template('manage_users.html', users=users)




# صفحة تسجيل الدخول
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    تسجيل الدخول للمستخدم. يتطلب إدخال اسم المستخدم وكلمة المرور.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["orgname"] = user["orgname"]  # حفظ orgname في الجلسة (إن وُجد)
            session["role"] = user["role"]

            flash("تم تسجيل الدخول بنجاح", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("اسم المستخدم أو كلمة المرور غير صحيحة", "danger")

    return render_template("login.html")

# صفحة التسجيل
@app.route("/register", methods=["GET", "POST"])
#@login_required

def register():
    """
    تسجيل مستخدم جديد. يمكن أن يكون المستخدم "فرد" أو "منظمة".
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        orgname = request.form.get("orgname", None)
        hashed_password = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()

        # التحقق من تكرار اسم المستخدم
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash("اسم المستخدم موجود بالفعل. الرجاء اختيار اسم آخر.", "warning")
            conn.close()
            return redirect(url_for("register"))

        # إضافة المستخدم إلى قاعدة البيانات
        if role == "منظمة" and orgname:
            cursor.execute(
                "INSERT INTO users (username, password, role, orgname) VALUES (?, ?, ?, ?)",
                (username, hashed_password, role, orgname),
            )
        else:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role),
            )
        conn.commit()
        conn.close()

        flash("تم التسجيل بنجاح.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")

# صفحة لوحة التحكم
@app.route("/dashboard")
@login_required
def dashboard():
    """
    تعرض إحصائيات بسيطة عن عدد المستفيدين وكميات الموارد المتوفرة.
    """
    conn = get_db()
    cursor = conn.cursor()
    orgname = session.get("orgname")

    # إحصائيات لوحة التحكم
    cursor.execute("SELECT COUNT(*) FROM beneficiaries WHERE org = ?", (orgname,))
    beneficiaries_count = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(quantity) FROM resources WHERE org = ?", (orgname,))
    resources_total = cursor.fetchone()[0] or 0

    conn.close()

    return render_template(
        "dashboard.html",
        beneficiaries_count=beneficiaries_count,
        resources_total=resources_total
    )

# صفحة عرض المستفيدين
@app.route("/show_beneficiaries")
@login_required
def show_beneficiaries():
    """
    عرض جميع المستفيدين التابعين للمنظمة المسجّل حسابها.
    """
    orgname = session.get("orgname")
    conn = get_db()
    cursor = conn.cursor()

    # جلب بيانات المستفيدين
    cursor.execute("""
        SELECT name, national_id, contact_number, address, family_members
        FROM beneficiaries
        WHERE org = ?
    """, (orgname,))
    beneficiaries = cursor.fetchall()
    conn.close()

    return render_template("show_beneficiaries.html", beneficiaries=beneficiaries)

# صفحة الموارد الموزّعة على مستفيد معيّن
@app.route("/beneficiary_resources/<string:national_id>")
@login_required
def beneficiary_resources(national_id):
    """
    عرض الموارد الموزعة لمستفيد معيّن حسب رقمه الوطني.
    """
    orgname = session.get("orgname")
    conn = get_db()
    cursor = conn.cursor()

    # استعلام لاسترجاع الموارد الموزعة بناءً على national_id
    cursor.execute("""
        SELECT rd.date,re.doner,rd.resource_name, rd.quantity
        FROM resources_DE rd
        inner join resources re ON rd.resource_id = re.id
        WHERE rd.org = ? AND rd.national_id = ? order by rd.date desc
    """, (orgname, national_id))
    resources = cursor.fetchall()
    conn.close()

    return render_template("beneficiary_resources.html", resources=resources)

# صفحة إضافة مستفيد
@app.route("/add_beneficiary", methods=["GET", "POST"])
@login_required
def add_beneficiary():
    """
    إضافة مستفيد جديد. يجب التأكد من عدم تكرار رقم الهوية (national_id).
    """
    orgname = session.get("orgname")
    if not orgname:
        flash("لا يمكن إضافة مستفيد لأن المنظمة غير محددة.", "danger")
        return redirect(url_for('login'))

    if request.method == "POST":
        name = request.form["beneficiary_name"]
        national_id = request.form["national_id"]
        contact_number = request.form["contact_number"]
        address = request.form["address"]
        family_members = request.form["family_members"]

        conn = get_db()
        cursor = conn.cursor()

        # التحقق من تكرار رقم الهوية
        cursor.execute("SELECT org FROM beneficiaries WHERE national_id = ?", (national_id,))
        existing_beneficiary = cursor.fetchone()

        if existing_beneficiary:
            # إشعار المستخدم بوجود المستفيد واسم المنظمة التي يتبع لها
            flash(f"هذا المستفيد موجود بالفعل في : {existing_beneficiary['org']}", "warning")
            conn.close()
            return redirect(url_for('add_beneficiary'))

        # إضافة المستفيد إذا لم يكن موجودًا
        cursor.execute("""
            INSERT INTO beneficiaries (
                name, national_id, contact_number, address, family_members, org
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, national_id, contact_number, address, family_members, orgname))

        conn.commit()
        conn.close()

        flash("تم إضافة المستفيد بنجاح", "success")
        return redirect(url_for('add_beneficiary'))

    return render_template("add_beneficiary.html")
# حذف المستفيد
@app.route('/delete_beneficiary/<string:national_id>', methods=['GET', 'POST'])
@login_required
def delete_beneficiary(national_id):
    """
    حذف مستفيد بناءً على رقم الهوية (national_id).
    """
    conn = get_db()
    cursor = conn.cursor()

    # التحقق من وجود المستفيد
    cursor.execute("SELECT * FROM beneficiaries WHERE national_id = ?", (national_id,))
    beneficiary = cursor.fetchone()

    if beneficiary:
        # حذف المستفيد من قاعدة البيانات
        cursor.execute("DELETE FROM beneficiaries WHERE national_id = ?", (national_id,))
        conn.commit()
        conn.close()

        flash("تم حذف المستفيد بنجاح", "success")
        return redirect(url_for('show_beneficiaries'))
    else:
        # إذا لم يتم العثور على المستفيد
        conn.close()
        flash("لم يتم العثور على المستفيد", "danger")
        return redirect(url_for('show_beneficiaries'))

# جلب المستفيدين الذين لم يُخصص لهم المورد المعين
@app.route('/get_non_beneficiaries', methods=['GET'])
@login_required
def get_non_beneficiaries():
    """
    تُعيد JSON لمستفيدين لم يحصلوا على المورد المعيّن (resource_id)، أو حصلوا عليه بكمية 0.
    """
    resource_id = request.args.get('resource_id')
    orgname = session.get("orgname")

    # التأكد من وجود resource_id وorgname
    if not resource_id or not orgname:
        return jsonify({'error': 'Resource ID and Organization name are required'}), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT b.id, b.name, b.family_members, b.address, SUM(rd.quantity) as quantity,b.national_id

        FROM beneficiaries b
        left JOIN resources_DE rd
          ON b.national_id = rd.national_id AND rd.resource_id = ?
        WHERE  b.org = ?
        GROUP BY b.id, b.name, b.family_members, b.address,b.national_id
        ORDER BY b.name ASC;
    """, (resource_id, orgname))

    beneficiaries = cursor.fetchall()
    conn.close()
    # إعادة النتائج كـ JSON
    return jsonify([
        {
            'id': b[0],
            'name': b[1],
            'family_members': b[2],
            'address': b[3],
            'quantity': b[4],  # الكمية المخصصة للمورد (إن وجدت)
            'national_id':b[5]
        }
        for b in beneficiaries
    ])

# صفحة توزيع الموارد
@app.route("/resources_distribution", methods=["GET", "POST"])
@login_required
def resources_distribution():
    """
    صفحة لإضافة مورد جديد (وتخزينه في جدول resources) وعرض الموارد المتبقية.
    """
    orgname = session.get("orgname")

    if request.method == "POST":
        # بدلاً من استخدام resource_name كاسم المانح، نفصلها لزيادة الوضوح
        doner_name = request.form["resource_name"]      # اسم المتبرع
        item_name = request.form["item_name"]           # اسم المورد الفعلي
        quantity = int(request.form["quantity"].replace(",", ""))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO resources (resource_name, doner, quantity, org)
            VALUES (?, ?, ?, ?)
        """, (item_name, doner_name, quantity, orgname))
        conn.commit()
        conn.close()

        flash("تم إضافة المورد بنجاح", "success")
        return redirect(url_for('resources_distribution'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM resources WHERE quantity <> 0 AND org = ?", (orgname,))
    resources = cursor.fetchall() or []
    conn.close()

    return render_template("resources_distribution.html", resources=resources)

# مسار توزيع مورد محدد على مجموعة من المستفيدين
@app.route('/distribute', methods=['POST'])
@login_required
def distribute():
    """
    عند توزيع مورد معين (resource_id) على مجموعة من المستفيدين،
    نحدِّث الكمية المتبقية في جدول resources، ونضيف سجلات التوزيع في resources_DE.
    """
    resource_id = request.form['resource_id']

    # كميات التوزيع على المستفيدين، مفصولة بفواصل
    quantities = request.form['quantities'].split(',')
    quantities = [int(q) for q in quantities]  # تحويل إلى أعداد صحيحة

    # رقم الهوية للمستفيدين (قد يكون لديهم أكثر من مستفيد)
    national_ids = request.form['national_ids'].split(',')
    resource_name = request.form['resource_name']
    distribution_date = datetime.date.today().isoformat()  # Today's date in YYYY-MM-DD format
    orgname = session.get("orgname")

    conn = get_db()
    cursor = conn.cursor()

    # التحقق من توفر كمية كافية في الموارد قبل التوزيع
    cursor.execute("SELECT quantity FROM resources WHERE id = ?", (resource_id,))
    current_quantity = cursor.fetchone()
    if not current_quantity:
        conn.close()
        return jsonify({'status': 'error', 'message': 'المورد غير موجود!'})

    current_quantity = current_quantity[0]
    total_requested = sum(quantities)

    if total_requested > current_quantity:
        conn.close()
        return jsonify({'status': 'error', 'message': 'الكمية المطلوبة أكبر من المتوفر!'})

    # طرح الكمية الموزعة من المخزون
    cursor.execute("""
        UPDATE resources
        SET quantity = quantity - ?
        WHERE id = ?
    """, (total_requested, resource_id))

    # إضافة سجلات التوزيع في جدول resources_DE
    for i, national_id in enumerate(national_ids):
        cursor.execute("""
            INSERT INTO resources_DE (
                national_id, resource_name, resource_id, quantity, date, org
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (national_id, resource_name, resource_id, quantities[i], distribution_date, orgname))

    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': 'تم توزيع الموارد بنجاح'})

# صفحة الإحصائيات

@app.route('/statistics')
@login_required
def statistics():
    """
    عرض الإحصائيات المتعلقة بالمستفيدين والموارد الموزعة.
    """
    today = datetime.date.today().isoformat()

    orgname = session.get("orgname")
    conn = get_db()
    cursor = conn.cursor()

    # إحصائيات المستفيدين الذين حصلوا على موارد
    cursor.execute("""SELECT COUNT(DISTINCT national_id) FROM resources_DE WHERE org = ?""", (orgname,))
    beneficiaries_with_resources = cursor.fetchone()[0]

    # إحصائيات عدد المستفيدين خلال اليوم
    cursor.execute("""SELECT COUNT(DISTINCT national_id) FROM resources_DE WHERE org = ? AND date = ?""", (orgname, today))
    beneficiaries_today = cursor.fetchone()[0] or 0

    # إحصائيات عدد المستفيدين خلال الشهر
    cursor.execute("""SELECT COUNT(DISTINCT national_id) FROM resources_DE WHERE org = ? AND strftime('%Y-%m', date) = strftime('%Y-%m', 'now')""", (orgname,))
    beneficiaries_this_month = cursor.fetchone()[0] or 0

    # إحصائيات عدد المستفيدين خلال السنة
    cursor.execute("""SELECT COUNT(DISTINCT national_id) FROM resources_DE WHERE org = ? AND strftime('%Y', date) = strftime('%Y', 'now')""", (orgname,))
    beneficiaries_this_year = cursor.fetchone()[0] or 0

    # إحصائيات الموارد الموزعة
    cursor.execute("""SELECT resource_name, SUM(quantity) as quantity FROM resources_DE WHERE org = ? GROUP BY resource_name ORDER BY resource_name ASC""", (orgname,))
    total_resources_distributed = dict(cursor.fetchall())

    # إحصائيات الموارد الموزعة خلال اليوم
    cursor.execute("""SELECT resource_name, SUM(quantity) as quantity FROM resources_DE WHERE org = ? AND date = ? GROUP BY resource_name ORDER BY resource_name ASC""", (orgname, today))
    resources_today = dict(cursor.fetchall())

    # إحصائيات الموارد الموزعة خلال الشهر
    cursor.execute("""SELECT resource_name, SUM(quantity) as quantity FROM resources_DE WHERE org = ? AND strftime('%Y-%m', date) = strftime('%Y-%m', 'now') GROUP BY resource_name ORDER BY resource_name ASC""", (orgname,))
    resources_this_month = dict(cursor.fetchall())

    # إحصائيات الموارد المتبقية
    cursor.execute("""SELECT resource_name, SUM(quantity) as quantity FROM resources WHERE org = ? AND quantity > 0 GROUP BY resource_name ORDER BY resource_name ASC""", (orgname,))
    remaining_resources = dict(cursor.fetchall())


    conn.close()

    return render_template(
        "statistics.html",
        beneficiaries_with_resources=beneficiaries_with_resources,
        beneficiaries_today=beneficiaries_today,
        beneficiaries_this_month=beneficiaries_this_month,
        beneficiaries_this_year=beneficiaries_this_year,
        total_resources_distributed=total_resources_distributed,
        resources_today=resources_today,
        resources_this_month=resources_this_month,
        remaining_resources=remaining_resources,
    )


locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

# Create a custom filter for formatting numbers
@app.template_filter('comma')
def comma_filter(value):
    try:
        return locale.format_string("%d", value, grouping=True)
    except (ValueError, TypeError):
        return value




# صفحة تسجيل الخروج
@app.route("/logout")
def logout():
    """
    تسجيل خروج المستخدم وإلغاء الجلسة.
    """
    session.pop("user_id", None)
    session.pop("orgname", None)
    flash("تم تسجيل الخروج بنجاح", "info")
    return redirect(url_for("login"))

# ----------------------------------------------------------------
#  نقطة بدء تشغيل التطبيق
# ----------------------------------------------------------------
if __name__ == "__main__":
    init_db()  # تأكد من إنشاء الجداول في قاعدة البيانات
    app.run(debug=True)  # لا تستخدم debug=True في الإنتاج
