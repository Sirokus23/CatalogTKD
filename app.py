from flask import Flask, app, render_template, request, redirect, session, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from functools import wraps
from datetime import date, time, timedelta, datetime
import os
import secrets
from dotenv import load_dotenv


#Importurile necesare pentru realizarea acestuii proiects

load_dotenv()

def coach_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if current_user.role != 'antrenor':
            flash("Doar antrenorul are acces la această pagină.", "error")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)
    return wrapped
#Crearea decoratorului care impune conditia ca doar antrenorul poate accesa anumite resurse

db = SQLAlchemy()#initializarea bazei de date

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grupa_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    grupa = db.relationship("Group")
    nume = db.Column(db.String(50))
    prenume = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20), default='sportiv')  # 'user' or 'admin'
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expira = db.Column(db.DateTime, nullable=True)
    sesiune = db.relationship("TrainingSession")
    #Clasa utilizatorilor contine numele prenumee parola(cu hash) email-ul si relatiile cu alte tabele din baza de date

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nume_grup = db.Column(db.String(50))
    #Clasa grupelor create contine nr grupei si denumirea

class TrainingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grupa_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    grupa = db.relationship("Group")
    data = db.Column(db.Date)
    ora = db.Column(db.Time)
    notite = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = True)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_plata = db.Column(db.Date, nullable=False)
    perioada = db.Column(db.String(50))  # ex: "Octombrie 2026"
    platitor = db.relationship("User")

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grupa_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    grupa = db.relationship("Group")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    session_id = db.Column(db.Integer, db.ForeignKey('training_session.id'))
    prezenta = db.Column(db.Boolean, default=False)

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") #seteaza o parola secreta
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2) #limita sesiunii
    app.config["COD_INVITATIE"] = os.environ.get("COD_INVITATIE") #Variabile ascunse necesare
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    #Configurarile pentru aplicatie web

    mail = Mail(app)
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
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

            utilizator_nou = User(nume=nume, prenume=prenume, email=email, password=parola_hash) #Crearea utilizatorului nou inregistrat in baza de date

            db.session.add(utilizator_nou) #Adaugarea utilizatorului in baza de date.
            db.session.commit()
            flash("Înregistrare reușită! Te poți autentifica acum.", "success")
            return redirect(url_for("login"))   #redirectionarea

        return render_template("register.html")   #Generearea paginii html

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form["email"]
            raw_password = request.form["password"]

            utilizator = User.query.filter_by(email=email).first()
            if utilizator and check_password_hash(utilizator.password, raw_password):
                session.permanent = True
                login_user(utilizator)
                flash("Autentificare reușită!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Email sau parolă incorectă.", "error")
                return redirect(url_for("login"))
        return render_template("login.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=current_user)

    @app.route("/schedule", methods=["GET", "POST"])
    @login_required
    def schedule():
        if request.method == "POST":
            data = date.fromisoformat(request.form["data"])
            ora = time.fromisoformat(request.form["ora"])
            grupa_id = request.form.get("grupa_id")

            sesiune_noua = TrainingSession(data=data, ora=ora, grupa_id=int(grupa_id) if grupa_id else None, user_id = current_user.id)
            db.session.add(sesiune_noua)
            db.session.commit()
            flash("Sesiune de antrenament programată cu succes.", "success")
            return redirect(url_for("schedule"))

        
        if current_user.role == 'antrenor':
            sesiuni = TrainingSession.query.all()
        else:
            sesiuni = TrainingSession.query.filter((TrainingSession.grupa_id == current_user.grupa_id) | (TrainingSession.grupa_id.is_(None))).all()

        grupe = Group.query.all()
        return render_template("schedule.html", sesiuni=sesiuni, grupe=grupe, user=current_user)

    @app.route("/schedule/<int:session_id>/edit", methods = ["GET", "POST"])
    @login_required
    @coach_required
    def edita_sesiune(session_id):
        sesiune = TrainingSession.query.get_or_404(session_id)

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
        return render_template("edita_sesiunea.html", sesiune = sesiune, grupe = grupe)

    @app.route("/attendance/<int:session_id>", methods=["GET", "POST"])
    @login_required
    @coach_required
    def attendance(session_id):
        sesiune = TrainingSession.query.get_or_404(session_id)
        sportivi = User.query.filter_by(role='sportiv').all()

        if sesiune.grupa_id:
            sportivi = User.query.filter_by(role='sportiv', grupa_id=sesiune.grupa_id).all()
        else:
            sportivi = User.query.filter_by(role='sportiv').all()

        if request.method == "POST":
            for sportiv in sportivi:
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

        prezente_curente = {a.user_id: a.prezenta for a in Attendance.query.filter_by(session_id=session_id).all()}
        return render_template("attendance.html", sesiune=sesiune, sportivi=sportivi, prezente_curente=prezente_curente, user=current_user)

    @app.route("/payments", methods=["GET", "POST"])
    @login_required
    def payments():
        if request.method == "POST":
            user_id = int(request.form["user_id"])
            data_plata = date.fromisoformat(request.form["data_plata"])
            perioada = request.form["perioada"]

            plata_noua = Payment(user_id=user_id, data_plata=data_plata, perioada=perioada)
            db.session.add(plata_noua)
            db.session.commit()
            flash("Plata a fost înregistrată cu succes.", "success")
            return redirect(url_for("payments"))

        if current_user.role == 'antrenor':
            sportivi = User.query.filter_by(role='sportiv').all()
            plati = Payment.query.order_by(Payment.data_plata.desc()).all()
            return render_template("payments.html", sportivi=sportivi, plati=plati, user=current_user)
        else:
            plati_proprii = Payment.query.filter_by(user_id=current_user.id).order_by(Payment.data_plata.desc()).all()
            return render_template("payments.html", plati_proprii=plati_proprii, user=current_user)

    @app.route("/roster", methods=["GET", "POST"])
    @login_required
    @coach_required
    def roster():
        if request.method == "POST":
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
                sportiv.grupa_id = int(grupa_id) if grupa_id else None
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
                utilizator.reset_token = token
                utilizator.reset_token_expira = datetime.utcnow() + timedelta(minutes=30)
                db.session.commit()

                link_resetare = url_for("reset_password", token=token, _external=True)
                msg = Message("Resetare parolă", sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f"Pentru a reseta parola, accesează următorul link: {link_resetare}\nAcest link va expira în 30 de minute."
                mail.send(msg)

            flash("Dacă adresa există în sistem, vei primi un email cu instrucțiuni.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
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
    app = create_app()
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=False)