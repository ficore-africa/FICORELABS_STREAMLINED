import logging
import datetime
from bson import ObjectId
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import FloatField, StringField, DateField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, NumberRange, ValidationError
from translations import trans
from utils import requires_role, get_mongo_db, initialize_tools_with_urls

logger = logging.getLogger(__name__)

taxation_bp = Blueprint('taxation_bp', __name__, template_folder='templates/taxation')

# Forms
class TaxCalculationForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(message=trans('tax_amount_required', default='Amount is required')), NumberRange(min=0, message=trans('tax_amount_non_negative', default='Amount must be non-negative'))], render_kw={'class': 'form-control'})
    pension = FloatField('Pension Contribution', validators=[NumberRange(min=0, message=trans('tax_pension_non_negative', default='Pension contribution must be non-negative'))], default=0, render_kw={'class': 'form-control'})
    rent_relief = FloatField('Rent Relief', validators=[NumberRange(min=0, message=trans('tax_rent_relief_non_negative', default='Rent relief must be non-negative'))], default=0, render_kw={'class': 'form-control'})
    taxpayer_type = SelectField('Taxpayer Type', choices=[
        ('paye', trans('tax_paye', default='PAYE (Personal)')),
        ('small_business', trans('tax_small_business', default='Small Business')),
        ('cit', trans('tax_cit', default='CIT (Company Income Tax)')),
        ('vat', trans('tax_vat', default='VAT (Value Added Tax)'))
    ], validators=[DataRequired(message=trans('tax_type_required', default='Taxpayer type is required'))], render_kw={'class': 'form-select'})
    business_size = SelectField('Business Size', choices=[
        ('', trans('tax_select_size', default='Select Size')),
        ('small', trans('tax_small', default='Small (≤ ₦50M)')),
        ('large', trans('tax_large', default='Large (> ₦50M)'))
    ], render_kw={'class': 'form-select'})
    vat_category = SelectField('VAT Category', choices=[
        ('', trans('tax_select_category', default='Select Category')),
        ('food', trans('tax_food', default='Food')),
        ('healthcare', trans('tax_healthcare', default='Healthcare')),
        ('education', trans('tax_education', default='Education')),
        ('rent', trans('tax_rent', default='Rent')),
        ('power', trans('tax_power', default='Power')),
        ('baby_products', trans('tax_baby_products', default='Baby Products')),
        ('other', trans('tax_other', default='Other'))
    ], render_kw={'class': 'form-select'})
    tax_year = SelectField('Tax Year', choices=[
        ('2025', '2025'),
        ('2026', '2026')
    ], validators=[DataRequired(message=trans('tax_year_required', default='Tax year is required'))], render_kw={'class': 'form-select'})
    is_business_vat = BooleanField('Business VAT Credit', render_kw={'class': 'form-check-input'})
    submit = SubmitField(trans('tax_calculate', default='Calculate Tax'), render_kw={'class': 'btn btn-primary w-100'})

    def validate_business_size(self, field):
        if self.taxpayer_type.data in ['small_business', 'cit'] and not field.data:
            raise ValidationError(trans('tax_business_size_required', default='Business size is required'))

    def validate_vat_category(self, field):
        if self.taxpayer_type.data == 'vat' and not field.data:
            raise ValidationError(trans('tax_vat_category_required', default='VAT category is required'))

class TaxRateForm(FlaskForm):
    role = SelectField('Role', choices=[
        ('personal', trans('tax_personal', default='Personal')),
        ('trader', trans('tax_trader', default='Trader')),
        ('agent', trans('tax_agent', default='Agent')),
        ('company', trans('tax_company', default='Company')),
        ('vat', trans('tax_vat', default='VAT'))
    ], validators=[DataRequired(message=trans('tax_role_required', default='Role is required'))], render_kw={'class': 'form-select'})
    min_income = FloatField('Minimum Income', validators=[DataRequired(message=trans('tax_min_income_required', default='Minimum income is required')), NumberRange(min=0, message=trans('tax_min_income_non_negative', default='Minimum income must be non-negative'))], render_kw={'class': 'form-control'})
    max_income = FloatField('Maximum Income', validators=[DataRequired(message=trans('tax_max_income_required', default='Maximum income is required')), NumberRange(min=0, message=trans('tax_max_income_non_negative', default='Maximum income must be non-negative'))], render_kw={'class': 'form-control'})
    rate = FloatField('Rate', validators=[DataRequired(message=trans('tax_rate_required', default='Rate is required')), NumberRange(min=0, max=1, message=trans('tax_rate_range', default='Rate must be between 0 and 1'))], render_kw={'class': 'form-control'})
    description = StringField('Description', validators=[DataRequired(message=trans('tax_description_required', default='Description is required'))], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('tax_add_rate', default='Add Tax Rate'), render_kw={'class': 'btn btn-primary w-100'})

class ReminderForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired(message=trans('tax_message_required', default='Message is required'))], render_kw={'class': 'form-control'})
    reminder_date = DateField('Reminder Date', validators=[DataRequired(message=trans('tax_reminder_date_required', default='Reminder date is required'))], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('tax_add_reminder', default='Add Reminder'), render_kw={'class': 'btn btn-primary w-100'})

# Tax Calculation Functions
def calculate_paye_2025(taxable_income):
    if not isinstance(taxable_income, (int, float)) or taxable_income < 0:
        logger.error(f"Invalid taxable_income: {taxable_income}")
        raise ValueError("Taxable income must be a non-negative number")
    brackets = [
        (300000, 0.07),
        (300000, 0.11),
        (500000, 0.15),
        (500000, 0.19),
        (float('inf'), 0.21)
    ]
    tax_due = 0
    remaining = taxable_income
    for limit, rate in brackets:
        if remaining > limit:
            tax_due += limit * rate
            remaining -= limit
        else:
            tax_due += remaining * rate
            break
    explanation = trans('tax_paye_explanation_2025', default=f"PAYE 2025: Tax calculated on ₦{taxable_income:,.2f} with brackets 7% up to ₦300,000, 11% next ₦300,000, 15% next ₦500,000, 19% next ₦500,000, 21% above ₦1,600,000")
    return round(tax_due, 2), explanation

def calculate_paye_2026(taxable_income):
    if not isinstance(taxable_income, (int, float)) or taxable_income < 0:
        logger.error(f"Invalid taxable_income: {taxable_income}")
        raise ValueError("Taxable income must be a non-negative number")
    brackets = [
        (800000, 0.0),
        (2200000, 0.15),
        (9000000, 0.18),
        (13000000, 0.21),
        (25000000, 0.23),
        (float('inf'), 0.25)
    ]
    tax_due = 0
    remaining = taxable_income
    for limit, rate in brackets:
        if remaining > limit:
            tax_due += limit * rate
            remaining -= limit
        else:
            tax_due += remaining * rate
            break
    explanation = trans('tax_paye_explanation_2026', default=f"PAYE 2026: Tax calculated on ₦{taxable_income:,.2f} with brackets 0% up to ₦800,000, 15% next ₦2,200,000, 18% next ₦9,000,000, 21% next ₦13,000,000, 23% next ₦25,000,000, 25% above ₦50,000,000")
    return round(tax_due, 2), explanation

def calculate_paye_tax(year, gross, pension, rent_relief):
    logger.debug(f"calculate_paye_tax inputs: year={year}, gross={gross}, pension={pension}, rent_relief={rent_relief}")
    if not all(isinstance(x, (int, float)) and x >= 0 for x in [gross, pension, rent_relief]):
        logger.error(f"Invalid inputs: gross={gross}, pension={pension}, rent_relief={rent_relief}")
        raise ValueError("All inputs must be non-negative numbers")
    try:
        year = int(year)
        if year < 0:
            raise ValueError("Tax year cannot be negative")
    except ValueError as e:
        logger.error(f"Invalid tax year: {year}, error: {str(e)}")
        raise
    if year >= 2026:
        taxable = max(0, gross - pension - rent_relief)
        return calculate_paye_2026(taxable)
    else:
        relief = (gross - pension) * 0.2
        cra = 200000
        taxable = max(0, gross - pension - relief - cra)
        return calculate_paye_2025(taxable)

def calculate_vat(amount, category, is_business=False):
    if not isinstance(amount, (int, float)) or amount < 0:
        logger.error(f"Invalid VAT amount: {amount}")
        raise ValueError("Amount must be a non-negative number")
    if not category:
        logger.error("Invalid VAT category: None")
        return 0.0, trans('tax_invalid_vat_category', default='Invalid VAT category')
    exempt_categories = ["food", "healthcare", "education", "rent", "power", "baby_products"]
    if category in exempt_categories:
        return 0.0, trans('tax_vat_exempt', default=f"{category.capitalize()} is VAT-exempt")
    vat_rate = 0.075
    vat_due = amount * vat_rate
    explanation = trans('tax_vat_applied', default=f"{vat_rate*100}% VAT applied")
    if is_business:
        vat_due = 0.0
        explanation = trans('tax_vat_reclaimed', default="Input VAT reclaimed for business")
    return round(vat_due, 2), explanation

def calculate_cit(turnover, tax_year):
    if not isinstance(turnover, (int, float)) or turnover < 0:
        logger.error(f"Invalid turnover: {turnover}")
        raise ValueError("Turnover must be a non-negative number")
    try:
        tax_year = int(tax_year)
        if tax_year < 0:
            raise ValueError("Tax year cannot be negative")
    except ValueError as e:
        logger.error(f"Invalid tax year: {tax_year}, error: {str(e)}")
        raise
    if tax_year <= 2025:
        if turnover <= 25000000:
            tax = 0.0
            explanation = trans('tax_cit_explanation_small_2025', default="0% CIT for turnover ≤ ₦25M in 2025, simplified return, no audit")
            simplified_return = True
            audit_required = False
        elif turnover <= 100000000:
            tax = turnover * 0.25
            explanation = trans('tax_cit_explanation_medium_2025', default="25% CIT for turnover ₦25M+ to ₦100M in 2025")
            simplified_return = False
            audit_required = True
        else:
            tax = turnover * 0.30
            explanation = trans('tax_cit_explanation_large_2025', default="30% CIT for turnover > ₦100M in 2025")
            simplified_return = False
            audit_required = True
    else:  # 2026 onward
        if turnover <= 50000000:
            tax = 0.0
            explanation = trans('tax_cit_explanation_small', default="0% CIT for turnover ≤ ₦50M, simplified return, no audit")
            simplified_return = True
            audit_required = False
        else:
            tax = turnover * 0.30
            explanation = trans('tax_cit_explanation_large', default="30% CIT for turnover > ₦50M")
            simplified_return = False
            audit_required = True
    return round(tax, 2), explanation, simplified_return, audit_required

def tax_summary(name, gross_income, pension, rent_relief, turnover, vat_amount, vat_category, is_business_vat, tax_year):
    if not all(isinstance(x, (int, float)) and x >= 0 for x in [gross_income, pension, rent_relief, turnover, vat_amount]):
        logger.error(f"Invalid inputs in tax_summary: gross_income={gross_income}, pension={pension}, rent_relief={rent_relief}, turnover={turnover}, vat_amount={vat_amount}")
        raise ValueError("All monetary inputs must be non-negative numbers")
    if not tax_year:
        logger.error("Tax year is missing")
        raise ValueError("Tax year is required")
    try:
        tax_year = int(tax_year)
    except ValueError:
        logger.error(f"Invalid tax year: {tax_year}")
        raise ValueError("Tax year must be a valid number")
    paye, paye_explanation = calculate_paye_tax(tax_year, gross_income, pension, rent_relief)
    cit, cit_explanation, simplified_return, audit_required = calculate_cit(turnover, tax_year)
    vat, vat_explanation = calculate_vat(vat_amount, vat_category, is_business_vat)
    return {
        "name": name,
        "gross_income": gross_income,
        "pension": pension,
        "rent_relief": rent_relief,
        "monthly_paye": round(paye / 12, 2),
        "annual_paye": paye,
        "paye_explanation": paye_explanation,
        "sme_turnover": turnover,
        "sme_cit": cit,
        "cit_explanation": cit_explanation,
        "simplified_return": simplified_return,
        "audit_required": audit_required,
        "vat_amount": vat_amount,
        "vat_tax": vat,
        "vat_explanation": vat_explanation
    }

# Database Seeding
def seed_tax_data(force_reseed=False):
    db = get_mongo_db()
    # Check if seeding is needed or forced
    if not force_reseed and db.config.find_one({'key': 'tax_data_seeded'}):
        logger.info("Tax data already seeded, skipping unless forced")
        # Verify that vat_rules has data
        vat_count = db.vat_rules.count_documents({})
        if vat_count == 0:
            logger.warning("vat_rules collection is empty, forcing re-seeding")
            force_reseed = True
        else:
            logger.info(f"Found {vat_count} VAT rules, seeding not required")
            return
    try:
        # Drop existing collections if forcing reseed
        if force_reseed:
            logger.info("Force reseeding tax data")
            db.tax_rates.drop()
            db.vat_rules.drop()
            db.payment_locations.drop()
            db.tax_reminders.drop()
            db.config.delete_one({'key': 'tax_data_seeded'})

        # Create collections if they don't exist
        for collection in ['tax_rates', 'vat_rules', 'payment_locations', 'tax_reminders']:
            if collection not in db.list_collection_names():
                db.create_collection(collection)
                logger.info(f"Created collection: {collection}")

        # Seed tax rates
        if db.tax_rates.count_documents({}) == 0:
            tax_rates = [
                {'role': 'personal', 'min_income': 0.0, 'max_income': 300000.0, 'rate': 0.07, 'description': trans('tax_rate_personal_7_2025', default='7% PAYE for income up to ₦300,000 in 2025, with 20% relief and ₦200,000 CRA'), 'year': 2025},
                {'role': 'personal', 'min_income': 300001.0, 'max_income': 600000.0, 'rate': 0.11, 'description': trans('tax_rate_personal_11_2025', default='11% PAYE for income ₦300,001 to ₦600,000 in 2025'), 'year': 2025},
                {'role': 'personal', 'min_income': 600001.0, 'max_income': 1100000.0, 'rate': 0.15, 'description': trans('tax_rate_personal_15_2025', default='15% PAYE for income ₦600,001 to ₦1,100,000 in 2025'), 'year': 2025},
                {'role': 'personal', 'min_income': 1100001.0, 'max_income': 1600000.0, 'rate': 0.19, 'description': trans('tax_rate_personal_19_2025', default='19% PAYE for income ₦1,100,001 to ₦1,600,000 in 2025'), 'year': 2025},
                {'role': 'personal', 'min_income': 1600001.0, 'max_income': float('inf'), 'rate': 0.21, 'description': trans('tax_rate_personal_21_2025', default='21% PAYE for income above ₦1,600,000 in 2025'), 'year': 2025},
                {'role': 'personal', 'min_income': 0.0, 'max_income': 800000.0, 'rate': 0.0, 'description': trans('tax_rate_personal_0_2026', default='0% PAYE for income up to ₦800,000 in 2026'), 'year': 2026},
                {'role': 'personal', 'min_income': 800001.0, 'max_income': 3000000.0, 'rate': 0.15, 'description': trans('tax_rate_personal_15_2026', default='15% PAYE for income ₦800,001 to ₦3,000,000 in 2026'), 'year': 2026},
                {'role': 'personal', 'min_income': 3000001.0, 'max_income': 12000000.0, 'rate': 0.18, 'description': trans('tax_rate_personal_18_2026', default='18% PAYE for income ₦3,000,001 to ₦12,000,000 in 2026'), 'year': 2026},
                {'role': 'personal', 'min_income': 12000001.0, 'max_income': 25000000.0, 'rate': 0.21, 'description': trans('tax_rate_personal_21_2026', default='21% PAYE for income ₦12,000,001 to ₦25,000,000 in 2026'), 'year': 2026},
                {'role': 'personal', 'min_income': 25000001.0, 'max_income': 50000000.0, 'rate': 0.23, 'description': trans('tax_rate_personal_23_2026', default='23% PAYE for income ₦25,000,001 to ₦50,000,000 in 2026'), 'year': 2026},
                {'role': 'personal', 'min_income': 50000001.0, 'max_income': float('inf'), 'rate': 0.25, 'description': trans('tax_rate_personal_25_2026', default='25% PAYE for income above ₦50,000,000 in 2026'), 'year': 2026},
                {'role': 'company', 'min_income': 0.0, 'max_income': 25000000.0, 'rate': 0.0, 'description': trans('tax_rate_cit_small_2025', default='0% CIT for turnover ≤ ₦25M in 2025, simplified return, no audit'), 'year': 2025},
                {'role': 'company', 'min_income': 25000001.0, 'max_income': 100000000.0, 'rate': 0.25, 'description': trans('tax_rate_cit_medium_2025', default='25% CIT for turnover ₦25M+ to ₦100M in 2025'), 'year': 2025},
                {'role': 'company', 'min_income': 100000001.0, 'max_income': float('inf'), 'rate': 0.30, 'description': trans('tax_rate_cit_large_2025', default='30% CIT for turnover > ₦100M in 2025'), 'year': 2025},
                {'role': 'company', 'min_income': 0.0, 'max_income': 50000000.0, 'rate': 0.0, 'description': trans('tax_rate_cit_small', default='0% CIT for turnover ≤ ₦50M, simplified return, no audit'), 'year': 2026},
                {'role': 'company', 'min_income': 50000001.0, 'max_income': float('inf'), 'rate': 0.30, 'description': trans('tax_rate_cit_large', default='30% CIT for turnover > ₦50M'), 'year': 2026}
            ]
            inserted_count = db.tax_rates.insert_many(tax_rates).inserted_ids
            logger.info(f"Seeded {len(inserted_count)} tax rates")
            if len(inserted_count) != len(tax_rates):
                logger.error(f"Failed to seed all tax rates: expected {len(tax_rates)}, inserted {len(inserted_count)}")
                raise Exception("Incomplete tax rates seeding")

        # Seed VAT rules
        if db.vat_rules.count_documents({}) == 0:
            vat_rules = [
                {'category': cat, 'vat_exempt': True, 'description': trans(f'tax_vat_exempt_{cat}', default=f'{cat.capitalize()} is exempt from VAT')} for cat in ['food', 'healthcare', 'education', 'rent', 'power', 'baby_products']
            ] + [
                {'category': 'business_credit', 'vat_exempt': False, 'description': trans('tax_vat_reclaimed', default='Input VAT reclaimed for business')}
            ]
            inserted_count = db.vat_rules.insert_many(vat_rules).inserted_ids
            logger.info(f"Seeded {len(inserted_count)} VAT rules")
            if len(inserted_count) != len(vat_rules):
                logger.error(f"Failed to seed all VAT rules: expected {len(vat_rules)}, inserted {len(inserted_count)}")
                raise Exception("Incomplete VAT rules seeding")

        # Seed payment locations
        if db.payment_locations.count_documents({}) == 0:
            locations = [
                {'name': 'Lagos NRS Office', 'address': '123 Broad Street, Lagos', 'contact': '+234-1-2345678'},
                {'name': 'Abuja NRS Office', 'address': '456 Garki Road, Abuja', 'contact': '+234-9-8765432'}
            ]
            inserted_count = db.payment_locations.insert_many(locations).inserted_ids
            logger.info(f"Seeded {len(inserted_count)} payment locations")
            if len(inserted_count) != len(locations):
                logger.error(f"Failed to seed all payment locations: expected {len(locations)}, inserted {len(inserted_count)}")
                raise Exception("Incomplete payment locations seeding")

        # Seed reminders
        if db.tax_reminders.count_documents({}) == 0:
            reminders = [
                {'user_id': 'admin', 'message': trans('tax_reminder_quarterly', default='File quarterly tax return with NRS'), 'reminder_date': datetime.datetime(2026, 3, 31), 'created_at': datetime.datetime.utcnow()}
            ]
            inserted_count = db.tax_reminders.insert_many(reminders).inserted_ids
            logger.info(f"Seeded {len(inserted_count)} reminders")
            if len(inserted_count) != len(reminders):
                logger.error(f"Failed to seed all reminders: expected {len(reminders)}, inserted {len(inserted_count)}")
                raise Exception("Incomplete reminders seeding")

        # Mark seeding as complete
        db.config.update_one(
            {'key': 'tax_data_seeded'},
            {'$set': {'key': 'tax_data_seeded', 'value': True}},
            upsert=True
        )
        logger.info("Tax data seeding completed successfully")
    except Exception as e:
        logger.error(f"Failed to seed tax data: {str(e)}")
        raise

# Routes
@taxation_bp.route('/calculate', methods=['GET', 'POST'])
@requires_role(['personal', 'trader', 'agent', 'company'])
@login_required
def calculate_tax():
    try:
        form = TaxCalculationForm()
        db = get_mongo_db()
        tax_rates = list(db.tax_rates.find({'role': {'$exists': True}}))
        vat_rules = list(db.vat_rules.find())
        logger.debug(f"Tax rates count: {len(tax_rates)}, VAT rules count: {len(vat_rules)}")
        # Log contents for debugging
        logger.debug(f"Tax rates: {[str(rate) for rate in tax_rates]}")
        logger.debug(f"VAT rules: {[str(rule) for rule in vat_rules]}")
        # Check if vat_rules is empty and provide fallback
        if not vat_rules:
            logger.warning("No VAT rules found, using default VAT rules")
            vat_rules = [
                {'category': 'default', 'vat_exempt': False, 'description': trans('tax_vat_default', default='Default 7.5% VAT applied'), '_id': 'default'}
            ]
            flash(trans('tax_vat_rules_missing', default='VAT rules are missing. Using default 7.5% VAT rate.'), 'warning')
        # Remove strict check to avoid error
        # if not tax_rates or not vat_rules:
        #     logger.error("Tax rates or VAT rules are missing from the database")
        #     flash(trans('tax_data_missing', default='Tax configuration data is missing. Please contact support.'), 'danger')
        #     return render_template(...)
        for rate in tax_rates:
            if 'role' not in rate:
                logger.warning(f"Unexpected tax_rates document without 'role': {rate}")
        for rule in vat_rules:
            if 'category' not in rule:
                logger.warning(f"Unexpected vat_rules document without 'category': {rule}")
        serialized_tax_rates = [
            {
                'role': rate.get('role', 'unknown'),
                'min_income': rate.get('min_income', 0.0),
                'max_income': rate.get('max_income', float('inf')),
                'rate': rate.get('rate', 0.0),
                'description': rate.get('description', ''),
                '_id': str(rate['_id']),
                'year': rate.get('year', '')
            } for rate in tax_rates if rate.get('_id') != 'version'
        ]
        serialized_vat_rules = [
            {
                'category': rule.get('category', 'unknown'),
                'vat_exempt': rule.get('vat_exempt', False),
                'description': rule.get('description', ''),
                '_id': str(rule['_id'])
            } for rule in vat_rules
        ]
        if request.method == 'POST':
            if form.validate_on_submit():
                amount = form.amount.data
                pension = form.pension.data
                rent_relief = form.rent_relief.data
                taxpayer_type = form.taxpayer_type.data
                business_size = form.business_size.data if taxpayer_type in ['small_business', 'cit'] else None
                vat_category = form.vat_category.data if taxpayer_type == 'vat' else None
                is_business_vat = form.is_business_vat.data if taxpayer_type == 'vat' else False
                tax_year = form.tax_year.data
                logger.info(f"POST /calculate: user={current_user.id}, amount={amount}, pension={pension}, rent_relief={rent_relief}, taxpayer_type={taxpayer_type}, business_size={business_size}, vat_category={vat_category}, is_business_vat={is_business_vat}, tax_year={tax_year}")
                total_tax = 0.0
                explanation = ""
                simplified_return = False
                audit_required = False
                if taxpayer_type == 'paye':
                    total_tax, explanation = calculate_paye_tax(tax_year, amount, pension, rent_relief)
                elif taxpayer_type in ['small_business', 'cit']:
                    if business_size not in ['small', 'large']:
                        flash(trans('tax_invalid_business_size', default='Invalid business size selected'), 'warning')
                        return render_template(
                            'taxation/taxation.html',
                            section='calculate',
                            form=form,
                            tax_rates=serialized_tax_rates,
                            vat_rules=serialized_vat_rules,
                            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
                            title=trans('tax_calculate_title', default='Calculate Tax', lang=session.get('lang', 'en'))
                        )
                    total_tax, explanation, simplified_return, audit_required = calculate_cit(amount, tax_year)
                elif taxpayer_type == 'vat':
                    if not vat_category:
                        flash(trans('tax_invalid_vat_category', default='VAT category required'), 'warning')
                        return render_template(
                            'taxation/taxation.html',
                            section='calculate',
                            form=form,
                            tax_rates=serialized_tax_rates,
                            vat_rules=serialized_vat_rules,
                            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
                            title=trans('tax_calculate_title', default='Calculate Tax', lang=session.get('lang', 'en'))
                        )
                    total_tax, explanation = calculate_vat(amount, vat_category, is_business_vat)
                logger.info(f"Tax calculated: user={current_user.id}, tax={total_tax}, explanation={explanation}, simplified_return={simplified_return}, audit_required={audit_required}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'tax': total_tax,
                        'explanation': explanation,
                        'amount': amount,
                        'pension': pension,
                        'rent_relief': rent_relief,
                        'simplified_return': simplified_return,
                        'audit_required': audit_required
                    })
                return render_template(
                    'taxation/taxation.html',
                    section='result',
                    tax=total_tax,
                    explanation=explanation,
                    amount=amount,
                    pension=pension,
                    rent_relief=rent_relief,
                    simplified_return=simplified_return,
                    audit_required=audit_required,
                    form=form,
                    tax_rates=serialized_tax_rates,
                    vat_rules=serialized_vat_rules,
                    policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
                    title=trans('tax_result_title', default='Tax Calculation Result', lang=session.get('lang', 'en'))
                )
            else:
                logger.error(f"Form validation failed: user={current_user.id}, errors={form.errors}")
                flash(trans('tax_invalid_input', default=f'Invalid input: {form.errors}'), 'danger')
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': trans('tax_invalid_input', default=f'Invalid input: {form.errors}')}), 400
        return render_template(
            'taxation/taxation.html',
            section='calculate',
            form=form,
            role=current_user.role,
            tax_rates=serialized_tax_rates,
            vat_rules=serialized_vat_rules,
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_calculate_title', default='Calculate Tax', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in calculate_tax: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while calculating tax. Please try again.'), 'danger')
        return render_template(
            'taxation/taxation.html',
            section='calculate',
            form=form,
            role=current_user.role,
            tax_rates=[],
            vat_rules=[],
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_calculate_title', default='Calculate Tax', lang=session.get('lang', 'en'))
        )

@taxation_bp.route('/payment_info', methods=['GET'])
@requires_role(['personal', 'trader', 'agent', 'company'])
@login_required
def payment_info():
    try:
        db = get_mongo_db()
        locations = list(db.payment_locations.find())
        serialized_locations = [
            {
                'name': loc.get('name', 'Unknown'),
                'address': loc.get('address', 'Unknown'),
                'contact': loc.get('contact', 'Unknown'),
                '_id': str(loc['_id'])
            } for loc in locations
        ]
        return render_template(
            'taxation/taxation.html',
            section='payment_info',
            locations=serialized_locations,
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_payment_info_title', default='Tax Payment Information', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in payment_info: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while retrieving payment information. Please try again.'), 'danger')
        return render_template(
            'taxation/taxation.html',
            section='payment_info',
            locations=[],
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_payment_info_title', default='Tax Payment Information', lang=session.get('lang', 'en'))
        )

@taxation_bp.route('/understand_taxes', methods=['GET'])
@requires_role(['personal', 'trader', 'agent', 'company'])
@login_required
def understand_taxes():
    try:
        return render_template(
            'taxation/taxation.html',
            section='understand_taxes',
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_understand_taxes_title', default='Understand Your Taxes', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in understand_taxes: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while loading tax information. Please try again.'), 'danger')
        return render_template(
            'taxation/taxation.html',
            section='understand_taxes',
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_understand_taxes_title', default='Understand Your Taxes', lang=session.get('lang', 'en'))
        )

@taxation_bp.route('/reminders', methods=['GET', 'POST'])
@requires_role(['personal', 'trader', 'agent', 'company'])
@login_required
def reminders():
    try:
        form = ReminderForm()
        db = get_mongo_db()
        if request.method == 'POST' and form.validate_on_submit():
            reminder = {
                'user_id': current_user.id,
                'message': form.message.data,
                'reminder_date': form.reminder_date.data,
                'created_at': datetime.datetime.utcnow()
            }
            result = db.tax_reminders.insert_one(reminder)
            logger.info(f"Reminder added: user={current_user.id}, message={form.message.data}, reminder_id={result.inserted_id}")
            flash(trans('tax_reminder_added', default='Reminder added successfully'), 'success')
            return redirect(url_for('taxation_bp.reminders'))
        reminders = list(db.tax_reminders.find({'user_id': current_user.id}))
        serialized_reminders = [
            {
                'message': rem.get('message', 'Unknown'),
                'reminder_date': rem.get('reminder_date'),
                'created_at': rem.get('created_at'),
                '_id': str(rem['_id']),
                'user_id': str(rem.get('user_id', 'Unknown'))
            } for rem in reminders
        ]
        return render_template(
            'taxation/taxation.html',
            section='reminders',
            form=form,
            reminders=serialized_reminders,
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_reminders_title', default='Tax Reminders', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in reminders: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while managing reminders. Please try again.'), 'danger')
        return render_template(
            'taxation/taxation.html',
            section='reminders',
            form=form,
            reminders=[],
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_reminders_title', default='Tax Reminders', lang=session.get('lang', 'en'))
        )

@taxation_bp.route('/admin/rates', methods=['GET', 'POST'])
@requires_role('admin')
@login_required
def manage_tax_rates():
    try:
        form = TaxRateForm()
        db = get_mongo_db()
        if request.method == 'POST' and form.validate_on_submit():
            tax_rate = {
                'role': form.role.data,
                'min_income': form.min_income.data,
                'max_income': form.max_income.data,
                'rate': form.rate.data,
                'description': form.description.data,
                'year': int(form.description.data.split()[-1]) if form.description.data.split()[-1].isdigit() else 2025  # Extract year from description or default to 2025
            }
            result = db.tax_rates.insert_one(tax_rate)
            logger.info(f"Tax rate added: user={current_user.id}, role={form.role.data}, rate={form.rate.data}, rate_id={result.inserted_id}")
            flash(trans('tax_rate_added', default='Tax rate added successfully'), 'success')
            return redirect(url_for('taxation_bp.manage_tax_rates'))
        rates = list(db.tax_rates.find({'role': {'$exists': True}}))
        vat_rules = list(db.vat_rules.find())
        logger.debug(f"Fetched tax_rates: {rates}")
        logger.debug(f"Fetched vat_rules: {vat_rules}")
        for rate in rates:
            if 'role' not in rate:
                logger.warning(f"Unexpected tax_rates document without 'role': {rate}")
        for rule in vat_rules:
            if 'category' not in rule:
                logger.warning(f"Unexpected vat_rules document without 'category': {rule}")
        serialized_rates = [
            {
                'role': rate.get('role', 'unknown'),
                'min_income': rate.get('min_income', 0.0),
                'max_income': rate.get('max_income', float('inf')),
                'rate': rate.get('rate', 0.0),
                'description': rate.get('description', ''),
                '_id': str(rate['_id']),
                'year': rate.get('year', '')
            } for rate in rates if rate.get('_id') != 'version'
        ]
        serialized_vat_rules = [
            {
                'category': rule.get('category', 'unknown'),
                'vat_exempt': rule.get('vat_exempt', False),
                'description': rule.get('description', ''),
                '_id': str(rule['_id'])
            } for rule in vat_rules
        ]
        return render_template(
            'taxation/taxation.html',
            section='admin_rates',
            form=form,
            rates=serialized_rates,
            vat_rules=serialized_vat_rules,
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_manage_rates_title', default='Manage Tax Rates', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in manage_tax_rates: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while managing tax rates. Please try again.'), 'danger')
        return render_template(
            'taxation/taxation.html',
            section='admin_rates',
            form=form,
            rates=[],
            vat_rules=[],
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_manage_rates_title', default='Manage Tax Rates', lang=session.get('lang', 'en'))
        )

@taxation_bp.route('/admin/locations', methods=['GET', 'POST'])
@requires_role('admin')
@login_required
def manage_payment_locations():
    try:
        db = get_mongo_db()
        if request.method == 'POST':
            name = request.form.get('name')
            address = request.form.get('address')
            contact = request.form.get('contact')
            if name and address and contact:
                result = db.payment_locations.insert_one({
                    'name': name,
                    'address': address,
                    'contact': contact
                })
                logger.info(f"Payment location added: user={current_user.id}, name={name}, location_id={result.inserted_id}")
                flash(trans('tax_location_added', default='Location added successfully'), 'success')
                return redirect(url_for('taxation_bp.manage_payment_locations'))
            else:
                logger.error(f"Invalid input for payment location: user={current_user.id}, name={name}, address={address}, contact={contact}")
                flash(trans('tax_invalid_input', default='Invalid input. Please check your fields.'), 'danger')
        locations = list(db.payment_locations.find())
        serialized_locations = [
            {
                'name': loc.get('name', 'Unknown'),
                'address': loc.get('address', 'Unknown'),
                'contact': loc.get('contact', 'Unknown'),
                '_id': str(loc['_id'])
            } for loc in locations
        ]
        return render_template(
            'taxation/taxation.html',
            section='admin_locations',
            locations=serialized_locations,
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_manage_locations_title', default='Manage Payment Locations', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in manage_payment_locations: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while managing payment locations. Please try again.'), 'danger')
        return render_template(
            'taxation/taxation.html',
            section='admin_locations',
            locations=[],
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_manage_locations_title', default='Manage Payment Locations', lang=session.get('lang', 'en'))
        )

@taxation_bp.route('/admin/deadlines', methods=['GET', 'POST'])
@requires_role('admin')
@login_required
def manage_tax_deadlines():
    try:
        db = get_mongo_db()
        if request.method == 'POST':
            deadline_date = request.form.get('deadline_date')
            description = request.form.get('description')
            if deadline_date and description:
                try:
                    deadline_date = datetime.datetime.strptime(deadline_date, '%Y-%m-%d')
                    result = db.tax_reminders.insert_one({
                        'deadline_date': deadline_date,
                        'description': description
                    })
                    logger.info(f"Tax deadline added: user={current_user.id}, description={description}, deadline_id={result.inserted_id}")
                    flash(trans('tax_deadline_added', default='Deadline added successfully'), 'success')
                except ValueError:
                    logger.error(f"Invalid date format for deadline: user={current_user.id}, date={deadline_date}")
                    flash(trans('tax_invalid_date', default='Invalid date format'), 'danger')
            else:
                logger.error(f"Invalid input for deadline: user={current_user.id}, date={deadline_date}, description={description}")
                flash(trans('tax_invalid_input', default='Invalid input. Please check your fields.'), 'danger')
            return redirect(url_for('taxation_bp.manage_tax_deadlines'))
        deadlines = list(db.tax_reminders.find())
        serialized_deadlines = [
            {
                'deadline_date': dl.get('deadline_date'),
                'description': dl.get('description', 'Unknown'),
                '_id': str(dl['_id'])
            } for dl in deadlines
        ]
        return render_template(
            'taxation/taxation.html',
            section='admin_deadlines',
            deadlines=serialized_deadlines,
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_manage_deadlines_title', default='Manage Tax Deadlines', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in manage_tax_deadlines: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while managing tax deadlines. Please try again.'), 'danger')
        return render_template(
            'taxation/taxation.html',
            section='admin_deadlines',
            deadlines=[],
            policy_notice=trans('tax_policy_notice', default='New tax laws effective 1 January 2026: Rent relief of ₦200,000 for income ≤ ₦1M, VAT exemptions for essentials, 0% CIT for small businesses ≤ ₦50M with simplified returns, 30% CIT for large businesses, VAT credits for businesses.'),
            title=trans('tax_manage_deadlines_title', default='Manage Tax Deadlines', lang=session.get('lang', 'en'))
        )

@taxation_bp.route('/admin/reseed', methods=['POST'])
@requires_role('admin')
@login_required
def reseed_tax_data():
    try:
        seed_tax_data(force_reseed=True)
        flash(trans('tax_data_reseeded', default='Tax data reseeded successfully'), 'success')
        return redirect(url_for('taxation_bp.manage_tax_rates'))
    except Exception as e:
        logger.error(f"Error in reseed_tax_data: user={current_user.id}, error={str(e)}")
        flash(trans('tax_general_error', default='An error occurred while reseeding tax data. Please try again.'), 'danger')
        return redirect(url_for('taxation_bp.manage_tax_rates'))
