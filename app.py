from flask import Flask, app, render_template, request, redirect, session, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from datetime import date, time, timedelta, datetime
import os
import secrets
from dotenv import load_dotenv

"""Pe data de 06/09 la 8:45 PM
    Am introdus urmatoarele masuri de securitate pentru aceasta aplicatie WEB:
    Am adaugat header-uri de securitate folosind flask-talisman, am adaugat configurari de securizare a cookiuri-lor
    Libraria flask-wtf pentru a proteja de Cross-Site Request Forger
    Si am introdus rata de limitare pentru paginile login,register si reset password
"""
#Importurile necesare pentru realizarea acestuii proiects

load_dotenv()  # Încarcă variabilele dintr-un fișier .env local în os.environ, doar pentru
               # dezvoltare locală. În producție (PythonAnywhere), secretele reale sunt setate
               # direct în fișierul WSGI, deoarece .env nu este niciodată încărcat pe server.

def coach_required(view_func):
    """Decorator: blochează întreaga rută (atât GET cât și POST) dacă current_user.role != 'antrenor'.
    Se folosește pe rutele care sunt EXCLUSIV pentru antrenor (ex: /roster, /attendance).
    NU te baza doar pe acest decorator pentru rute precum /schedule sau /payments, unde GET
    este comun ambelor roluri și doar POST trebuie restricționat — acelea au nevoie de o
    verificare manuală a rolului direct în funcție, deoarece acest decorator nu poate distinge
    "unele acțiuni, nu altele"."""
    @wraps(view_func)  # păstrează numele/metadatele funcției originale, astfel încât rutarea
                        # Flask (care identifică rutele după numele funcției) să nu se încurce
                        # din cauză că toate funcțiile decorate s-ar numi altfel "wrapped".
    def wrapped(*args, **kwargs):
        if current_user.role != 'antrenor':
            flash("Doar antrenorul are acces la această pagină.", "error")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)
    return wrapped
#Crearea decoratorului care impune conditia ca doar antrenorul poate accesa anumite resurse

db = SQLAlchemy()#initializarea bazei de date

class User(UserMixin, db.Model):
    # UserMixin oferă metodele is_authenticated / is_active / get_id() etc. de care
    # Flask-Login are nevoie pe orice obiect trimis către login_user() — fără el,
    # login_user() ar da eroare.
    id = db.Column(db.Integer, primary_key=True)
    grupa_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    grupa = db.relationship("Group")
    nume = db.Column(db.String(50))
    prenume = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))  # stochează un HASH (via generate_password_hash), niciodată parola brută
    role = db.Column(db.String(20), default='sportiv')  # 'user' or 'admin'
    reset_token = db.Column(db.String(100), nullable=True)       # token aleatoriu, de unică folosință, pentru resetarea parolei
    reset_token_expira = db.Column(db.DateTime, nullable=True)   # token-ul devine invalid după acest moment
    sesiune = db.relationship("TrainingSession")
    #Clasa utilizatorilor contine numele prenumee parola(cu hash) email-ul si relatiile cu alte tabele din baza de date

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nume_grup = db.Column(db.String(50))
    #Clasa grupelor create contine nr grupei si denumirea

class TrainingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grupa_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)  # NULL = vizibil pentru toată lumea ("toată echipa")
    grupa = db.relationship("Group")
    data = db.Column(db.Date)
    ora = db.Column(db.Time)
    notite = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # ^ reține CARE antrenor a creat această sesiune — folosit pentru verificarea IDOR
    #   (ownership) din edita_sesiune() mai jos, ca doar antrenorul care a creat-o să o poată edita.

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_plata = db.Column(db.Date, nullable=False)
    perioada = db.Column(db.String(50))  # ex: "Octombrie 2026"
    platitor = db.relationship("User")
    # ^ permite ca în template să accesăm plata.platitor.nume direct, fără un query separat

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grupa_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    grupa = db.relationship("Group")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    session_id = db.Column(db.Integer, db.ForeignKey('training_session.id'))
    prezenta = db.Column(db.Boolean, default=False)

# Extensiile sunt create aici, neasociate încă unei aplicații, și legate de obiectul real `app`
# mai jos în create_app() prin .init_app(app). Același model ca `db = SQLAlchemy()` de mai sus —
# permite ca acestea să fie importate/referite din alte părți ale fișierului înainte să existe
# efectiv aplicația Flask.
csrf = CSRFProtect()
limiter = Limiter(get_remote_address,  # urmărește/limitează cererile pe baza adresei IP a vizitatorului
                  default_limits=["200 per day", "50 per hour"]  # se aplică pe FIECARE rută, dacă nu e suprascris
                  )

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") #seteaza o parola secreta
    # ^ Folosit pentru a semna criptografic cookie-urile de sesiune ȘI token-urile CSRF.
    #   Dacă se scurge, un atacator ar putea falsifica sesiuni/token-uri valide — nu trebuie
    #   niciodată hardcodat sau urcat pe GitHub.
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2) #limita sesiunii
    app.config["COD_INVITATIE"] = os.environ.get("COD_INVITATIE") #Variabile ascunse necesare
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

    # Securizarea cookie-ului de sesiune:
    app.config['SESSION_COOKIE_SECURE'] = True    # cookie-ul e trimis doar prin HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript nu poate citi acest cookie —
                                                   # limitează pagubele chiar dacă ar exista o vulnerabilitate XSS
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # cookie-ul nu e trimis la majoritatea cererilor
                                                   # cross-site, ceea ce ajută și la blocarea CSRF la nivel de browser
    #Configurarile pentru aplicatie web

    csrf.init_app(app)      # activează verificarea token-ului CSRF pe fiecare cerere care modifică date (POST), pe toată aplicația
    limiter.init_app(app)   # activează limitele de rată definite mai sus
    Talisman(app)           # adaugă header-uri de securitate în răspuns (HSTS, X-Frame-Options, CSP etc.)
                             # și forțează HTTPS implicit — vezi discuția despre FORCE_HTTPS pentru excepțiile de dezvoltare locală
    mail = Mail(app)
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'  # unde Flask-Login redirecționează un utilizator anonim
                                         # care accesează o rută @login_required
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        # Flask-Login apelează asta la fiecare cerere pentru a reconstrui `current_user`
        # din id-ul utilizatorului stocat în cookie-ul de sesiune.
        return db.session.get(User, int(user_id))

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("3 per hour")  # mai strict decât limita globală — abuzul la înregistrare
                                   # (conturi spam, ghicirea codului de invitație) e un risc real
    def register():
        if request.method == "POST":
            nume = request.form["nume"]
            prenume = request.form["prenume"]
            email = request.form["email"]                                   #Toate datele introduse de utilizator pe interfata web
            raw_password = request.form["password"]
            confirmed_password = request.form["confirmed_password"]
            cod_invitatie = request.form["cod_invitatie"]

            if cod_invitatie != app.config["COD_INVITATIE"]:
                flash("Codul de invitație este incorect.", "error")         #Masura de securitate fiecare participant va avea acces la un cod care va prmite accesarea interfetei
                return redirect(url_for("register"))

            if not nume or not prenume or not email or not raw_password:    #Completarea obligatorie a tuturor cimpurilor necesare pentru inregistrare
                flash("Toate câmpurile sunt obligatorii.", "error")
                return redirect(url_for("register"))

            if len(raw_password) < 8 or not any(char.isdigit() for char in raw_password) or not any(char.isupper() for char in raw_password):       #Verificare slaba la cit de puternica este parola ---> Posibile schimbari in viitor
                flash("Parola trebuie să aibă cel puțin 8 caractere, să conțină cel puțin o literă mare și un număr.", "error")
                return redirect(url_for("register"))

            if User.query.filter_by(email=email).first():           #Verificare daca posta electronica introdusa este deja inregistrata
                flash("Email-ul există deja.", "error")
                return redirect(url_for("register"))

            if raw_password != confirmed_password:
                flash("Parolele nu coincid.", "error")          #Confirmarea parolei
                return redirect(url_for("register"))

            parola_hash = generate_password_hash(raw_password)
            # ^ Hashing PBKDF2/scrypt (implicit în Werkzeug) — deliberat lent, include automat
            #   o "sare" (salt) aleatorie, deci parole identice produc hash-uri diferite stocate,
            #   iar spargerea prin brute-force offline a bazei de date devine impracticabilă.

            utilizator_nou = User(nume=nume, prenume=prenume, email=email, password=parola_hash) #Crearea utilizatorului nou inregistrat in baza de date

            db.session.add(utilizator_nou) #Adaugarea utilizatorului in baza de date.
            db.session.commit()
            flash("Înregistrare reușită! Te poți autentifica acum.", "success")
            return redirect(url_for("login"))   #redirectionarea

        return render_template("register.html")   #Generearea paginii html

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")  # blochează ghicirea parolei prin brute-force pentru un email cunoscut
    def login():
        if request.method == "POST":
            email = request.form["email"]
            raw_password = request.form["password"]

            utilizator = User.query.filter_by(email=email).first()
            # check_password_hash re-hashuiește raw_password cu aceeași sare/algoritm stocate
            # în utilizator.password și compară — singurul mod corect de a verifica o parolă hash-uită.
            if utilizator and check_password_hash(utilizator.password, raw_password):
                session.permanent = True  # aplică PERMANENT_SESSION_LIFETIME (2h) acestei autentificări,
                                           # în loc să expire doar la închiderea browserului
                login_user(utilizator)
                flash("Autentificare reușită!", "success")
                return redirect(url_for("dashboard"))
            else:
                # Deliberat ACELAȘI mesaj de eroare indiferent dacă email-ul nu există sau
                # parola e greșită — previne un atacator să folosească mesaje diferite pentru
                # a afla care email-uri sunt de fapt înregistrate.
                flash("Email sau parolă incorectă.", "error")
                return redirect(url_for("login"))
        return render_template("login.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=current_user)

    @app.route("/schedule", methods=["GET", "POST"])
    @login_required  # oricine autentificat poate face GET (vizualiza) — doar @login_required, nu @coach_required,
                      # deoarece sportivii au nevoie de acces de citire la aceeași rută
    def schedule():
        if request.method == "POST":
            # Verificare de rol pe server — NECESARĂ aici specific pentru că formularul de
            # "adaugă sesiune" e ascuns în template doar pentru non-antrenori, ceea ce e o
            # comoditate de interfață, nu securitate reală. Fără această verificare, orice
            # sportiv autentificat ar putea trimite direct un POST (ocolind formularul ascuns)
            # și crea sesiuni. Găsit și reparat în timpul testării de securitate.
            if current_user.role != 'antrenor':
                flash("Doar antrenor poate acces")
                return redirect(url_for("schedule"))
            data = date.fromisoformat(request.form["data"])
            ora = time.fromisoformat(request.form["ora"])
            grupa_id = request.form.get("grupa_id")

            sesiune_noua = TrainingSession(data=data, ora=ora, grupa_id=int(grupa_id) if grupa_id else None, user_id=current_user.id)
            db.session.add(sesiune_noua)
            db.session.commit()
            flash("Sesiune de antrenament programată cu succes.", "success")
            return redirect(url_for("schedule"))

        # Antrenorii văd toate sesiunile; sportivii văd doar sesiunile pentru propria grupă,
        # plus orice sesiune fără grupă ("toată echipa"), destinată tuturor.
        if current_user.role == 'antrenor':
            sesiuni = TrainingSession.query.all()
        else:
            sesiuni = TrainingSession.query.filter((TrainingSession.grupa_id == current_user.grupa_id) | (TrainingSession.grupa_id.is_(None))).all()

        grupe = Group.query.all()
        return render_template("schedule.html", sesiuni=sesiuni, grupe=grupe, user=current_user)

    @app.route("/schedule/<int:session_id>/edit", methods=["GET", "POST"])
    @login_required
    @coach_required  # sigur de folosit aici (spre deosebire de /schedule) deoarece toată ruta
                      # e exclusiv pentru antrenor, de la capăt la capăt — sportivii nu au nevoie de acces GET partajat
    def edita_sesiune(session_id):
        sesiune = TrainingSession.query.get_or_404(session_id)

        # Protecție IDOR (Insecure Direct Object Reference): fără această verificare, ORICE
        # antrenor ar putea edita sesiunea ORICĂRUI alt antrenor doar ghicind/incrementând
        # session_id în URL. Aici confirmăm că antrenorul autentificat chiar deține această
        # sesiune specifică înainte de a permite GET (vizualizarea formularului precompletat)
        # sau POST (salvarea modificărilor).
        if sesiune.user_id != current_user.id:
            abort(403)

        if request.method == "POST":
            sesiune.data = date.fromisoformat(request.form['data'])
            sesiune.ora = time.fromisoformat(request.form['ora'])
            grupa_id = request.form['grupa_id']
            sesiune.grupa_id = int(grupa_id) if grupa_id else None

            db.session.commit()
            flash("Sesiune aactualizata cu succes")
            return redirect(url_for("schedule"))

        grupe = Group.query.all()
        return render_template("edita_sesiunea.html", sesiune=sesiune, grupe=grupe)

    @app.route("/attendance/<int:session_id>", methods=["GET", "POST"])
    @login_required
    @coach_required
    def attendance(session_id):
        sesiune = TrainingSession.query.get_or_404(session_id)
        sportivi = User.query.filter_by(role='sportiv').all()

        # Prezența e limitată doar la grupa sesiunii respective (nu tot lotul),
        # revenind la toți sportivii doar pentru sesiunile fără grupă ("toată echipa").
        if sesiune.grupa_id:
            sportivi = User.query.filter_by(role='sportiv', grupa_id=sesiune.grupa_id).all()
        else:
            sportivi = User.query.filter_by(role='sportiv').all()

        if request.method == "POST":
            for sportiv in sportivi:
                # Un checkbox HTML nebifat nu trimite NIMIC în datele formularului — .get() cu
                # o valoare implicită evită un KeyError pentru fiecare sportiv nemarcat prezent.
                prezenta = request.form.get(f"prezenta_{sportiv.id}") == "on"
                inregistrare = Attendance.query.filter_by(user_id=sportiv.id, session_id=session_id).first()
                if inregistrare:
                    inregistrare.prezenta = prezenta
                else:
                    inregistrare = Attendance(user_id=sportiv.id, session_id=session_id, prezenta=prezenta)
                    db.session.add(inregistrare)
            db.session.commit()
            flash("Prezența a fost actualizată cu succes.", "success")
            return redirect(url_for("attendance", session_id=session_id))

        # Dicționar construit dintr-o comprehension: creează {user_id: prezenta} o singură dată,
        # astfel încât template-ul să poată căuta statusul fiecărui sportiv instant (O(1)),
        # în loc să caute repetat într-o listă.
        prezente_curente = {a.user_id: a.prezenta for a in Attendance.query.filter_by(session_id=session_id).all()}
        return render_template("attendance.html", sesiune=sesiune, sportivi=sportivi, prezente_curente=prezente_curente, user=current_user)

    @app.route("/payments", methods=["GET", "POST"])
    @login_required  # același model de GET partajat ca la /schedule — sportivii trebuie să-și vadă propriul istoric
    def payments():
        if request.method == "POST":
            # Aceeași verificare de rol pe server ca la /schedule, cu același motiv: formularul
            # de "înregistrează o plată" e ascuns pentru sportivi la nivel de interfață, dar
            # asta singură nu oprește un POST direct.
            if current_user.role != 'antrenor':
                flash("Doar antrenor poate acces")
                return redirect(url_for("payments"))

            user_id = int(request.form["user_id"])
            data_plata = date.fromisoformat(request.form["data_plata"])
            perioada = request.form["perioada"]

            plata_noua = Payment(user_id=user_id, data_plata=data_plata, perioada=perioada)
            db.session.add(plata_noua)
            db.session.commit()
            flash("Plata a fost înregistrată cu succes.", "success")
            return redirect(url_for("payments"))

        # Antrenorii văd plățile tuturor; sportivii văd doar plățile proprii — niciodată
        # istoricul de plăți al altui sportiv.
        if current_user.role == 'antrenor':
            sportivi = User.query.filter_by(role='sportiv').all()
            plati = Payment.query.order_by(Payment.data_plata.desc()).all()
            return render_template("payments.html", sportivi=sportivi, plati=plati, user=current_user)
        else:
            plati_proprii = Payment.query.filter_by(user_id=current_user.id).order_by(Payment.data_plata.desc()).all()
            return render_template("payments.html", plati_proprii=plati_proprii, user=current_user)

    @app.route("/roster", methods=["GET", "POST"])
    @login_required
    @coach_required  # întreaga rută e exclusiv pentru antrenor — sigur de folosit decoratorul aici
    def roster():
        if request.method == "POST":
            # O singură rută gestionează TREI acțiuni diferite, distinse după care câmp din
            # formular a fost de fapt trimis (fiecare <form> separat de pe pagina roster
            # trimite un nume de câmp unic, diferit).
            if "nume_grupa_noua" in request.form:
                grupa_noua = Group(nume_grup=request.form["nume_grupa_noua"])
                db.session.add(grupa_noua)
                db.session.commit()
                flash("Grupă adăugată.", "success")
            elif "redenumeste_grupa_id" in request.form:
                grupa = db.session.get(Group, int(request.form["redenumeste_grupa_id"]))
                grupa.nume_grup = request.form["nume_nou"]
                db.session.commit()
                flash("Grupă redenumită.", "success")
            else:
                sportiv_id = int(request.form["sportiv_id"])
                grupa_id = request.form["grupa_id"]
                sportiv = db.session.get(User, sportiv_id)
                sportiv.grupa_id = int(grupa_id) if grupa_id else None  # selecție goală -> elimină grupa
                db.session.commit()
                flash("Grupă actualizată.", "success")
            return redirect(url_for("roster"))

        sportivi = User.query.filter_by(role='sportiv').all()
        grupe = Group.query.all()
        return render_template("roster.html", sportivi=sportivi, grupe=grupe, user=current_user)

    @app.route("/roster/grupa/<int:grupa_id>/sterge", methods=["POST"])
    @login_required
    @coach_required
    def sterge_grupa(grupa_id):
        # Se elimină ÎNTÂI toți sportivii aflați în această grupă, înainte de a șterge grupa
        # în sine — altfel acei sportivi ar rămâne cu un grupa_id care indică spre un rând
        # ce nu mai există (o referință externă orfană / foreign key invalid).
        User.query.filter_by(grupa_id=grupa_id).update({"grupa_id": None})
        grupa = db.session.get(Group, grupa_id)
        db.session.delete(grupa)
        db.session.commit()
        flash("Grupă ștearsă. Sportivii au rămas fără grupă.", "success")
        return redirect(url_for("roster"))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form["email"]
            utilizator = User.query.filter_by(email=email).first()

            if utilizator:
                token = secrets.token_urlsafe(32)
                # secrets (nu random!) e criptografic sigur — necesar aici, deoarece un token
                # predictibil ar permite unui atacator să reseteze parola oricui, ghicindu-l.
                utilizator.reset_token = token
                utilizator.reset_token_expira = datetime.utcnow() + timedelta(minutes=30)
                db.session.commit()

                link_resetare = url_for("reset_password", token=token, _external=True)
                msg = Message("Resetare parolă", sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f"Pentru a reseta parola, accesează următorul link: {link_resetare}\nAcest link va expira în 30 de minute."
                mail.send(msg)

            # Același mesaj flash indiferent dacă email-ul e sau nu înregistrat — previne un
            # atacator să testeze acest endpoint pentru a descoperi ce email-uri există în sistem
            # (user enumeration), același principiu ca la mesajul de eroare de la /login.
            flash("Dacă adresa există în sistem, vei primi un email cu instrucțiuni.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    @limiter.limit("3 per hour")  # limitează ghicirea prin brute-force a unui token valid
    def reset_password(token):
        utilizator = User.query.filter_by(reset_token=token).first()

        if not utilizator or utilizator.reset_token_expira < datetime.utcnow():
            flash("Link invalid sau expirat.", "error")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            parola_noua = request.form["password"]
            if len(parola_noua) < 8 or not any(c.isdigit() for c in parola_noua) or not any(c.isupper() for c in parola_noua):
                flash("Parola trebuie să aibă cel puțin 8 caractere, o literă mare și un număr.", "error")
                return redirect(url_for("reset_password", token=token))

            utilizator.password = generate_password_hash(parola_noua)
            # Ștergerea token-ului face acest link DE UNICĂ FOLOSINȚĂ — odată ce parola e
            # resetată, același link nu mai poate fi refolosit mai târziu (ex: dintr-un email
            # vechi lăsat deschis undeva).
            utilizator.reset_token = None
            utilizator.reset_token_expira = None
            db.session.commit()
            flash("Parola a fost resetată. Te poți autentifica acum.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Te-ai deconectat cu succes.", "success")
        return redirect(url_for("login"))

    return app

if __name__ == "__main__":
    # Acest bloc rulează DOAR când execuți `python app.py` direct — NU rulează niciodată în
    # producție pe PythonAnywhere, deoarece fișierul WSGI apelează create_app() direct.
    app = create_app()
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
        # NOTĂ: create_all() creează doar tabelele care nu există încă — nu adaugă niciodată
        # o coloană nouă la un tabel deja existent. Orice modificare a modelelor necesită
        # ștergerea și recrearea fișierului bazei de date (sau adoptarea Flask-Migrate ca
        # alternativă neconstructivă, odată ce vor exista date reale ale utilizatorilor).
    app.run(debug=False)