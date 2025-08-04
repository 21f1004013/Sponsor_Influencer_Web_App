# Importing Libraries and Frameworks
from flask import Flask, render_template, flash, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime
import seaborn as sns
import matplotlib.pyplot as plt

# Initializing Flask Instance
app = Flask(__name__)

# Adding the Flask Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///Mad1.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = '21f1004013'
app.secret_key = '21f1004013'

# Intialize Database instance and create Migration
db = SQLAlchemy()
migrate = Migrate(app, db)
login_manager = LoginManager(app)

# Creating Database Model User(Admn,Influencer, Sponsor), Campaign and Requests
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    _password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(25))
    industry = db.Column(db.String(20),nullable=True)
    budgets = db.Column(db.Integer)
    category = db.Column(db.String(20),nullable=True)
    niche = db.Column(db.String(20),nullable=True)
    reach = db.Column(db.String(20),nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    sponsor_campaigns = db.relationship('Campaign', foreign_keys='Campaign.sponsor_id', back_populates='sponsor')
    influencer_campaigns = db.relationship('Campaign', foreign_keys='Campaign.influencer_id', back_populates='influencer')
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self._password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self._password, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    description = db.Column(db.Text)
    start_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, index=True)
    budget = db.Column(db.Integer)
    visibility = db.Column(db.String(255) , default='public')
    progress = db.Column(db.Integer, default=0)
    flagged = db.Column(db.Boolean, default=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_campaign_sponsor_id'))
    influencer_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_campaign_influencer_id'), nullable=True)
    sponsor = db.relationship('User', foreign_keys=[sponsor_id], back_populates='sponsor_campaigns')
    influencer = db.relationship('User', foreign_keys=[influencer_id], back_populates='influencer_campaigns')


class AdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    messages = db.Column(db.Text)
    requirements = db.Column(db.Text)
    payment_amount = db.Column(db.Integer)
    sender = db.Column(db.String(30))
    negotiated_amount = db.Column(db.Integer, nullable=True)
    negotiation_status = db.Column(db.String(64), default='Pending')  # 'Pending', 'Proposed', 'Accepted', 'Rejected'
    status = db.Column(db.String(64), default= 'pending')  # 'Pending', 'Accepted', 'Rejected'
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id', name='fk_adrequest_campaign_id'))
    influencer_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_adrequest_influencer_id'))
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_adrequest_sponsor_id'))
    campaign = db.relationship('Campaign', backref='ad_requests')
    influencer = db.relationship('User', foreign_keys=[influencer_id], backref='influencer')

db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Home Page Route as Login Route
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
            return render_template('home.html')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user._password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'influencer':
                return redirect(url_for('influencer_dashboard'))
            elif user.role == 'sponsor':
                return redirect(url_for('sponsor_dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
                return render_template('home.html')
        else:
            flash('Invalid username or password.', 'danger')
            return render_template('home.html')
    return render_template('home.html')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Sponsor Registration Route
@app.route('/register_sponsor', methods=['GET', 'POST'])
def register_sponsor():
    if request.method == 'GET':
        return render_template('spon_regist.html')
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        industry = request.form['industry']
        budget = request.form['budget']
        user = User(username=username, email=email, role='sponsor', 
                    industry=industry, budgets=budget, _password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered sponsor!')
        return redirect(url_for('home'))
    return render_template('spon_regist.html')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Influencer Registration Route
@app.route('/register_influencer', methods=['GET', 'POST'])
def register_influencer():
    if request.method == 'GET':
        return render_template('influ_regist.html')
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        category = request.form['category']
        niche = request.form['niche']
        reach = request.form['reach']
        user = User(username=username, email=email, role='influencer', category=category, niche=niche, reach=reach, _password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered influencer!')
        return redirect(url_for('home'))
    return render_template('influ_regist.html')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ User Logout Route
@app.route('/logout', methods = ["GET","POST"])
@login_required
def logout():
    logout_user()
    return redirect("/")

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Admin Dashboard Route
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    campaigns = Campaign.query.all()
    users = User.query.all()  # Assuming blocked users are flagged users
    return render_template('admin_dash.html',campaigns=campaigns,users=users)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Sponsor Dashboard Route
@app.route('/sponsor_dashboard')
@login_required
def sponsor_dashboard():
    user = current_user
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('You do not have permission to access this page as you are blocked.', 'danger')
        return redirect(url_for('home'))
    sponsor = User.query.filter(User.role == user.role).first()

    return render_template('spon_dash.html', sponsor = sponsor)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Sponsor Requests Statistics Route
@app.route('/spon_stats')
@login_required
def spon_stats():
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('You do not have permission to access this page as you are blocked.', 'danger')
        return redirect(url_for('home'))
    pending_requests = AdRequest.query.join(Campaign).filter(
        Campaign.sponsor_id == current_user.id,
        AdRequest.status == 'Pending'
    ).all()
    
    accepted_requests = AdRequest.query.join(Campaign).filter(
        Campaign.sponsor_id == current_user.id,
        AdRequest.status == 'Accepted'
    ).all()
    
    rejected_requests = AdRequest.query.join(Campaign).filter(
    Campaign.sponsor_id == current_user.id,
    AdRequest.status == 'Rejected'
    ).all()


    return render_template('spon_stats.html', pending_requests=pending_requests, accepted_requests=accepted_requests,rejected_requests=rejected_requests)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Influencer Dashboard Route
@app.route('/influencer_dashboard')
@login_required
def influencer_dashboard():
    user = current_user
    if current_user.role != 'influencer' or current_user.blocked:
        flash('You do not have permission to access this page as you are blocked.', 'danger')
        return redirect(url_for('home'))
    influencer = User.query.filter(User.role == user.role).first()

    return render_template('influ_dash.html', influencer = influencer)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ User and Campaign Blocking/Unblocking Routes  
@app.route('/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    user.blocked = True
    db.session.commit()
    flash('User blocked successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.blocked = False
    db.session.commit()
    flash('User unblocked successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/block_campaign/<int:campaign_id>', methods=['POST'])
@login_required
def block_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.flagged = True
    db.session.commit()
    flash('Campaign blocked successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/unblock_campaign/<int:campaign_id>', methods=['POST'])
@login_required
def unblock_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.flagged = False
    db.session.commit()
    flash('Campaign unblocked successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Sponsor Add a campaign and edit that campaign
@app.route('/add_campaign', methods=['GET', 'POST'])
@login_required
def add_campaign():
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('You do not have permission to access this page as you are blocked.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        budget = request.form.get('budget')
        enddate = request.form.get('enddate')
        visibility = request.form.get('visibility')
        enddate = datetime.strptime(enddate, '%Y-%m-%d')
        if not name or not description or not budget:
            flash('All fields are required.', 'danger')
            return render_template('add_campaign.html')

        new_campaign = Campaign(name=name, description=description,visibility=visibility, budget=budget, end_date=enddate, sponsor_id=current_user.id, progress=0)
        db.session.add(new_campaign)
        db.session.commit()

        flash('Campaign successfully created.', 'success')
        return redirect(url_for('camp_list'))

    return render_template('add_campaign.html')

@app.route('/edit_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def edit_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if request.method == 'POST':
        campaign.name = request.form['name']
        campaign.description = request.form['description']
        campaign.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        campaign.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        campaign.budget = request.form['budget']
        campaign.visibility = request.form['visibility']
        db.session.commit()
        flash('Campaign updated successfully!', 'success')
        return redirect(url_for('camp_list'))
    return render_template('edit_campaign.html', campaign=campaign)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Admin Search page for Users and Campaigns and action page
@app.route('/admin_find_dashboard')
@login_required
def admin_find_dashboard():
    user = User.query.all()
    campaign = Campaign.query.all()
    return render_template('admin_find_dash.html', user=user, campaign=campaign)

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    user = User.query.filter_by(id =id).first()
    db.session.delete(user)
    db.session.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_find_dashboard'))

@app.route('/delete_campaign/<int:campaign_id>')
@login_required
def delete_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign deleted.', 'success')
    return redirect(url_for('admin_find_dashboard'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Sponsor Search page for Influencer
@app.route('/sponsor_find_dashboard')
@login_required
def sponsor_find_dashboard():
    user = User.query.filter_by(role='influencer').all()
    return render_template('spon_find_dash.html', user=user)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Deleting Pending Requests by Sponsor
@app.route('/delete_request/<int:request_id>', methods=['POST'])
@login_required
def delete_request(request_id):
    request_to_delete = AdRequest.query.get_or_404(request_id)
    if current_user.id != request_to_delete.sponsor_id:
        flash('You are not authorized to delete this request.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    db.session.delete(request_to_delete)
    db.session.commit()
    flash('Request deleted successfully.', 'success')
    return redirect(url_for('sponsor_dashboard'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ View Campaign Details
@app.route('/view_campaign/<int:campaign_id>')
@login_required
def view_campaign(campaign_id):
    user = current_user
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('view_campaign.html', campaign=campaign, user=user)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ All campaign List for Sponsors
@app.route('/spon_camp_list')
@login_required
def camp_list():
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('Only sponsors can see the list.', 'danger')
        return redirect(url_for('home'))
    ad_requests = AdRequest.query.all()
    campaigns = Campaign.query.filter_by(sponsor_id = current_user.id).all()
    return render_template('campaign_list_spon.html', ad_requests=ad_requests,campaigns=campaigns)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Only Public Campaigns List
@app.route('/public_campaign')
@login_required
def public_campaign():
    if current_user.role != 'influencer' or current_user.blocked:
        flash('Only sponsors can see the list.', 'danger')
        return redirect(url_for('home'))
    campaigns = Campaign.query.filter(Campaign.visibility == "public").all()
    return render_template('influ_public_camp.html', campaigns=campaigns)


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Sponsor send campaign Request to a specific Influencer
@app.route('/send_request/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def send_request(campaign_id):
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('Only sponsors can send requests.', 'danger')
        return redirect(url_for('home'))

    campaign = Campaign.query.get_or_404(campaign_id)
    if request.method == 'POST':
        influencer_id = request.form.get('influencer_id')
        messages = request.form.get('messages')
        requirements = request.form.get('requirements')
        payment_amount = request.form.get('payment_amount')

        new_request = AdRequest(
            campaign_id=campaign.id,
            influencer_id=influencer_id,
            messages=messages,
            requirements=requirements,
            payment_amount=payment_amount,
            status='Pending',
            sender = current_user.role,
            sponsor_id = current_user.id
        )

        db.session.add(new_request)
        db.session.commit()
        flash('Request sent successfully.', 'success')
        return redirect(url_for('sponsor_dashboard', campaign_id=campaign.id))

    influencers = User.query.filter_by(role='influencer').all()
    return render_template('send_request.html', campaign=campaign, influencers=influencers)

#~~~~~~~~~~~~~~ Influencer send request for Public Campaign to Creater Sponsor
@app.route('/send_request/<int:campaign_id>/<int:sponsor_id>')
@login_required
def influ_send_request(campaign_id, sponsor_id):
    # Ensure the current user is an influencer
    if current_user.role != 'influencer' or current_user.blocked:
        flash('Only influencers can send requests.', 'danger')
        return redirect(url_for('home'))
    # Check if the influencer has already sent a request for this campaign
    existing_request = AdRequest.query.filter_by(
        campaign_id=campaign_id, influencer_id=current_user.id).first()
    if existing_request:
        flash('You have already sent a request for this campaign.', 'warning')
        return redirect(url_for('public_campaign'))
    # Create a new AdRequest
    new_request = AdRequest(campaign_id=campaign_id, sponsor_id=sponsor_id ,
                            influencer_id=current_user.id,
                            messages="I am interested in your campaign.",
                            status='Pending',sender = current_user.role)
    db.session.add(new_request)
    db.session.commit()
    flash('Request sent successfully!', 'success')
    return redirect(url_for('public_campaign'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~ List of all requests sent from Influencer to Sponsor
@app.route('/sponsor_requests')
@login_required
def sponsor_requests():
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('Only sponsors can view requests.', 'danger')
        return redirect(url_for('home'))
    # Fetch all requests sent to the current sponsor's campaigns
    requests = db.session.query(
        AdRequest,
        User.username.label('influencer_name'),
        Campaign.name.label('campaign_name')
    ).join(User, User.id == AdRequest.influencer_id
    ).join(Campaign, Campaign.id == AdRequest.campaign_id
    ).filter(AdRequest.sponsor_id == current_user.id , AdRequest.sender =='influencer').all()
    # Fetch all requests sent by the current Influencer for negotiate campaign payments.
    nego_requests = db.session.query(
        AdRequest,
        User.username.label('influencer_name'),
        Campaign.name.label('campaign_name')
    ).join(User, User.id == AdRequest.influencer_id
    ).join(Campaign, Campaign.id == AdRequest.campaign_id
    ).filter(AdRequest.sponsor_id == current_user.id , AdRequest.negotiation_status == 'Proposed').all()

    return render_template('sponsor_requests.html', requests=requests,nego_requests=nego_requests)


#~~~~~~~~~~~~~~~~~~~~~~~ Sponsor Response to Requests sent by Influencer
@app.route('/sponsor_respond_request/<int:request_id>', methods=['POST'])
@login_required
def sponsor_respond_request(request_id):
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('Only sponsors can respond to requests.', 'danger')
        return redirect(url_for('home'))

    ad_request = AdRequest.query.get_or_404(request_id)
    if ad_request.sponsor_id != current_user.id:
        flash('You are not authorized to respond to this request.', 'danger')
        return redirect(url_for('sponsor_requests'))

    response = request.form.get('response')
    if response == 'accept':
        ad_request.status = 'Accepted'
        flash('You have accepted the request.', 'success')
    elif response == 'reject':
        ad_request.status = 'Rejected'
        flash('You have rejected the request.', 'danger')
    else:
        flash('Invalid response.', 'danger')

    db.session.commit()
    return redirect(url_for('sponsor_requests'))

#~~~~~~~~~~~~~~~ Influencer see and response requests send by Sponsor for Advertising for Campaign 
@app.route('/view_requests')
@login_required
def view_requests():
    if current_user.role != 'influencer' or current_user.blocked:
        flash('Only influencers can view requests.', 'danger')
        return redirect(url_for('home'))

    requests = db.session.query(
        AdRequest,
        User.username.label('sponsor_name'),
        Campaign.name.label('campaign_name')
    ).join(Campaign, Campaign.id == AdRequest.campaign_id) \
     .join(User, User.id == Campaign.sponsor_id) \
     .filter(AdRequest.influencer_id == current_user.id, AdRequest.sender =="sponsor").all()

    return render_template('view_requests.html', requests=requests)

@app.route('/respond_request/<int:request_id>', methods=['POST'])
@login_required
def respond_request(request_id):
    if current_user.role != 'influencer' or current_user.blocked:
        flash('Only influencers can respond to requests.', 'danger')
        return redirect(url_for('home'))

    ad_request = AdRequest.query.get_or_404(request_id)
    if ad_request.influencer_id != current_user.id:
        flash('You are not authorized to respond to this request.', 'danger')
        return redirect(url_for('view_requests'))

    response = request.form.get('response')
    if response == 'accept':
        ad_request.status = 'Accepted'
        campaign = Campaign.query.get(ad_request.campaign_id)
        campaign.progress += 1  # Increment the progress by 1
        flash('You have accepted the request.', 'success')
    elif response == 'reject':
        ad_request.status = 'Rejected'
        flash('You have rejected the request.', 'danger')
    else:
        flash('Invalid response.', 'danger')
        
    db.session.commit()
    return redirect(url_for('view_requests'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~ Negotiation Requests by Influencer and their Response by Sponsors
@app.route('/negotiate_request/<int:request_id>', methods=['POST'])
@login_required
def negotiate_request(request_id):
    if current_user.role != 'influencer' or current_user.blocked:
        flash('Only influencers can negotiate requests.', 'danger')
        return redirect(url_for('home'))

    ad_request = AdRequest.query.get_or_404(request_id)
    if ad_request.influencer_id != current_user.id:
        flash('You are not authorized to negotiate this request.', 'danger')
        return redirect(url_for('view_requests'))

    new_amount = request.form.get('negotiated_amount')
    if not new_amount or int(new_amount) <= 0:
        flash('Please provide a valid amount for negotiation.', 'danger')
        return redirect(url_for('view_requests'))

    ad_request.negotiated_amount = int(new_amount)
    ad_request.negotiation_status = 'Proposed'
    db.session.commit()

    flash('Negotiation request sent successfully!', 'success')
    return redirect(url_for('view_requests'))

@app.route('/respond_negotiation/<int:request_id>', methods=['POST'])
@login_required
def respond_negotiation(request_id):
    if current_user.role != 'sponsor' or current_user.blocked:
        flash('Only sponsors can respond to negotiation requests.', 'danger')
        return redirect(url_for('home'))

    ad_request = AdRequest.query.get_or_404(request_id)
    if ad_request.sponsor_id != current_user.id:
        flash('You are not authorized to respond to this request.', 'danger')
        return redirect(url_for('sponsor_requests'))

    response = request.form.get('response')
    if response == 'accept':
        ad_request.payment_amount = ad_request.negotiated_amount
        ad_request.negotiation_status = 'Accepted'
        ad_request.status = 'Accepted'
        flash('You have accepted the negotiation request.', 'success')
    elif response == 'reject':
        ad_request.negotiation_status = 'Rejected'
        flash('You have rejected the negotiation request.', 'danger')
    else:
        flash('Invalid response.', 'danger')

    db.session.commit()
    return redirect(url_for('sponsor_requests'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Search Route for Users, Campaign results
@app.route('/search', methods=['POST'])
def search():
    user = current_user.role
    query = request.form.get('query', '')
    action = request.form.get('action', '')
    if user =="admin":
        if action == "1":
            influencers = User.query.filter(User.role == 'influencer', User.username.ilike(f'%{query}%')).all()
            return render_template("admin_search_results.html", data="1", main_data=influencers)

        elif action == "2":
            sponsors = User.query.filter(User.role == 'sponsor', User.username.ilike(f'%{query}%')).all()
            return render_template("admin_search_results.html", data="2", main_data=sponsors)

        else:
            campaigns = Campaign.query.filter(Campaign.name.ilike(f'%{query}%')).all()
            return render_template("admin_search_results.html", data="3", campaigns=campaigns)
    elif user =="sponsor":
        if action == "1":
            influencers = User.query.filter(User.role == 'influencer', User.username.ilike(f'%{query}%')).all()
            return render_template("spon_search_results.html", data="1", main_data=influencers)
    elif user =="influencer":
            campaigns = Campaign.query.filter(Campaign.visibility == "public" ,Campaign.name.ilike(f'%{query}%')).all()
            return render_template("influ_public_camp_result.html", data="3", campaigns=campaigns)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Creating chart for Admin
def create_seaborn_plot(data, column_name, row_name, title, color_palette, location):
    plt.figure(figsize=(4, 4))
    sns.set_palette(color_palette)
    sns.barplot(x=column_name, y=row_name, data=data)
    plt.xticks(rotation=45, ha='right', fontsize=6)
    plt.title(title)
    plot_path = f'static/{location}'  # Save the plot to a static folder
    plt.savefig(plot_path)
    plt.close()
    
@app.route('/stats', methods=['GET'])
def stats():
    user = current_user.role
    if user == "admin":
        exact_influ = len(User.query.filter_by(role="influencer").all())
        exact_spon = len(User.query.filter_by(role="sponsor").all())
        top_campaigns = Campaign.query.order_by(Campaign.progress.desc()).limit(5).all()
        no_of_camp = len(Campaign.query.all())
        no_of_req = len(AdRequest.query.all())

        data = {'User Type': ['Influencer', 'Sponsor'], 'Count': [exact_influ, exact_spon]}
        top_campaigns_data = {
            'Campaign Name': [campaign.name for campaign in top_campaigns],
            'progress': [campaign.progress for campaign in top_campaigns]
        }
        data1 = {'main': ['No of Campaign', 'No of Requests'], 'Count': [no_of_camp, no_of_req]}

        create_seaborn_plot(data, 'User Type', 'Count'
                            , 'Number of Influencers and sponsors', "Set2", 'spon_influ_plot.png')

        create_seaborn_plot(top_campaigns_data, 'Campaign Name', 'progress',
                            'Top 5 Campaigns by Progress', "viridis", 'campaign_progress.png')

        create_seaborn_plot(data1, 'main', 'Count',
                            'No of Campaigns and Requests', "viridis", 'campaign_requests.png')

        return render_template("admin_stats_dash.html")
    
if __name__ == '__main__':
    app.run(debug=True)