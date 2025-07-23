from flask import Blueprint, render_template, redirect, url_for, flash, request, Response, jsonify, session
from flask_login import login_required, current_user
from translations import trans
import utils
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, FloatField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional
import logging
import io

logger = logging.getLogger(__name__)

class ReceiptForm(FlaskForm):
    party_name = StringField(trans('receipts_party_name', default='Customer Name'), validators=[DataRequired()])
    date = DateField(trans('general_date', default='Date'), validators=[DataRequired()])
    amount = FloatField(trans('general_amount', default='Sale Amount'), validators=[DataRequired()])
    method = SelectField(trans('general_payment_method', default='Payment Method'), choices=[
        ('cash', trans('general_cash', default='Cash')),
        ('card', trans('general_card', default='Card')),
        ('bank', trans('general_bank_transfer', default='Bank Transfer'))
    ], validators=[Optional()])
    category = StringField(trans('general_category', default='Category'), validators=[Optional()])
    contact = StringField(trans('general_contact', default='Contact'), validators=[Optional()])  # Added contact field
    description = StringField(trans('general_description', default='Description'), validators=[Optional()])  # Added description field
    submit = SubmitField(trans('receipts_add_receipt', default='Record Sale'))

receipts_bp = Blueprint('receipts', __name__, url_prefix='/receipts')

@receipts_bp.route('/')
@login_required
@utils.requires_role('trader')
def index():
    """List all sales income cashflows for the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'receipt'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'receipt'}
        receipts = list(db.cashflows.find(query).sort('created_at', -1))
        return render_template(
            'receipts/index.html',
            receipts=receipts,
            format_currency=utils.format_currency,
            format_date=utils.format_date,
            title=trans('receipts_title', default='Money In', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching receipts for user {current_user.id}: {str(e)}")
        flash(trans('receipts_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@receipts_bp.route('/manage')
@login_required
@utils.requires_role('trader')
def manage():
    """Manage all receipt cashflows for the current user (edit/delete)."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'receipt'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'receipt'}
        receipts = list(db.cashflows.find(query).sort('created_at', -1))
        return render_template(
            'receipts/manage.html',
            receipts=receipts,
            format_currency=utils.format_currency,
            format_date=utils.format_date,
            title=trans('receipts_manage', default='Manage Receipts', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching receipts for manage page for user {current_user.id}: {str(e)}")
        flash(trans('receipts_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/view/<id>')
@login_required
@utils.requires_role('trader')
def view(id):
    """View detailed information about a specific receipt."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'receipt'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            return jsonify({'error': trans('receipts_record_not_found', default='Record not found')}), 404
        receipt['_id'] = str(receipt['_id'])
        receipt['created_at'] = receipt['created_at'].isoformat() if receipt.get('created_at') else None
        return jsonify(receipt)
    except Exception as e:
        logger.error(f"Error fetching receipt {id} for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans('receipts_fetch_error', default='An error occurred')}), 500

@receipts_bp.route('/generate_pdf/<id>')
@login_required
@utils.requires_role('trader')
def generate_pdf(id):
    """Generate PDF receipt for a receipt transaction."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'receipt'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            flash(trans('receipts_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('receipts.index'))
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            flash(trans('debtors_insufficient_credits', default='Insufficient credits to generate receipt'), 'danger')
            return redirect(url_for('credits.request_credits'))
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, height - inch, "FiCore Records - Money In Receipt")
        p.setFont("Helvetica", 12)
        y_position = height - inch - 0.5 * inch
        p.drawString(inch, y_position, f"Payer: {receipt['party_name']}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Amount Received: {utils.format_currency(receipt['amount'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Payment Method: {receipt.get('method', 'N/A')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Category: {receipt.get('category', 'No category provided')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Date: {utils.format_date(receipt['created_at'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Receipt ID: {str(receipt['_id'])}")
        y_position -= 0.3 * inch
        if receipt.get('contact'):
            p.drawString(inch, y_position, f"Contact: {receipt['contact']}")
            y_position -= 0.3 * inch
        if receipt.get('description'):
            p.drawString(inch, y_position, f"Description: {receipt['description']}")
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, "This document serves as an official receipt generated by FiCore Records.")
        p.showPage()
        p.save()
        if not utils.is_admin():
            user_query = utils.get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Receipt PDF generated for {receipt['party_name']} (Ficore Credits)"
            })
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=receipt_{receipt["party_name"]}_{str(receipt["_id"])}.pdf'
            }
        )
    except Exception as e:
        logger.error(f"Error generating PDF for receipt {id}: {str(e)}")
        flash(trans('receipts_pdf_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role('trader')
def add():
    """Add a new receipt cashflow."""
    form = ReceiptForm()
    if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
        flash(trans('debtors_insufficient_credits', default='Insufficient credits to add a receipt. Request more credits.'), 'danger')
        return redirect(url_for('credits.request_credits'))
    if form.validate_on_submit():
        try:
            db = utils.get_mongo_db()
            receipt_date = datetime(form.date.data.year, form.date.data.month, form.date.data.day)
            cashflow = {
                'user_id': str(current_user.id),
                'type': 'receipt',
                'party_name': form.party_name.data,
                'amount': form.amount.data,
                'method': form.method.data,
                'category': form.category.data,
                'contact': form.contact.data or None,  # Store contact
                'description': form.description.data or None,  # Store description
                'created_at': receipt_date,
                'updated_at': datetime.utcnow()
            }
            db.cashflows.insert_one(cashflow)
            if not utils.is_admin():
                user_query = utils.get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
                db.ficore_credit_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -1,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Receipt creation: {cashflow['party_name']} (Ficore Credits)"
                })
            flash(trans('receipts_add_success', default='Receipt added successfully'), 'success')
            return redirect(url_for('receipts.index'))
        except Exception as e:
            logger.error(f"Error adding receipt for user {current_user.id}: {str(e)}")
            flash(trans('receipts_add_error', default='An error occurred'), 'danger')
    return render_template(
        'receipts/add.html',
        form=form,
        title=trans('receipts_add_title', default='Add Money In', lang=session.get('lang', 'en'))
    )

@receipts_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('trader')
def edit(id):
    """Edit an existing receipt cashflow."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'receipt'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        receipt = db.cashflows.find_one(query)
        if not receipt:
            flash(trans('receipts_record_not_found', default='Cashflow not found'), 'danger')
            return redirect(url_for('receipts.index'))
        form = ReceiptForm(data={
            'party_name': receipt['party_name'],
            'date': receipt['created_at'],
            'amount': receipt['amount'],
            'method': receipt.get('method'),
            'category': receipt.get('category'),
            'contact': receipt.get('contact'),  # Populate contact
            'description': receipt.get('description')  # Populate description
        })
        if form.validate_on_submit():
            try:
                receipt_date = datetime(form.date.data.year, form.date.data.month, form.date.data.day)
                updated_cashflow = {
                    'party_name': form.party_name.data,
                    'amount': form.amount.data,
                    'method': form.method.data,
                    'category': form.category.data,
                    'contact': form.contact.data or None,  # Update contact
                    'description': form.description.data or None,  # Update description
                    'created_at': receipt_date,
                    'updated_at': datetime.utcnow()
                }
                db.cashflows.update_one({'_id': ObjectId(id)}, {'$set': updated_cashflow})
                flash(trans('receipts_edit_success', default='Receipt updated successfully'), 'success')
                return redirect(url_for('receipts.index'))
            except Exception as e:
                logger.error(f"Error updating receipt {id} for user {current_user.id}: {str(e)}")
                flash(trans('receipts_edit_error', default='An error occurred'), 'danger')
        return render_template(
            'receipts/edit.html',
            form=form,
            receipt=receipt,
            title=trans('receipts_edit_title', default='Edit Receipt', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching receipt {id} for user {current_user.id}: {str(e)}")
        flash(trans('receipts_record_not_found', default='Cashflow not found'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role('trader')
def delete(id):
    """Delete a receipt cashflow."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'receipt'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'receipt'}
        result = db.cashflows.delete_one(query)
        if result.deleted_count:
            flash(trans('receipts_delete_success', default='Receipt deleted successfully'), 'success')
        else:
            flash(trans('receipts_record_not_found', default='Cashflow not found'), 'danger')
        return redirect(url_for('receipts.index'))
    except Exception as e:
        logger.error(f"Error deleting receipt {id} for user {current_user.id}: {str(e)}")
        flash(trans('receipts_delete_error', default='An error occurred'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/share', methods=['POST'])
@login_required
@utils.requires_role('trader')
def share():
    """Share a receipt via SMS or WhatsApp."""
    try:
        if not utils.is_admin() and not utils.check_ficore_credit_balance(2):
            return jsonify({
                'success': False,
                'message': trans('debtors_insufficient_credits', default='Insufficient credits to share receipt')
            }), 403
        data = request.get_json()
        receipt_id = data.get('receiptId')
        recipient = data.get('recipient')
        message = data.get('message')
        share_type = data.get('type')
        if not all([receipt_id, recipient, message, share_type]):
            return jsonify({
                'success': False,
                'message': trans('receipts_missing_fields', default='Missing required fields')
            }), 400
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(receipt_id), 'type': 'receipt'} if utils.is_admin() else {
            '_id': ObjectId(receipt_id), 'user_id': str(current_user.id), 'type': 'receipt'
        }
        receipt = db.cashflows.find_one(query)
        if not receipt:
            return jsonify({
                'success': False,
                'message': trans('receipts_record_not_found', default='Receipt not found')
            }), 404
        # Placeholder for actual SMS/WhatsApp integration
        # Assuming utils.send_message handles the communication
        success = utils.send_message(recipient=recipient, message=message, type=share_type)
        if success:
            if not utils.is_admin():
                user_query = utils.get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -2}})
                db.ficore_credit_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -2,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Receipt shared with {recipient} via {share_type} (Ficore Credits)"
                })
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'message': trans('receipts_share_failed', default='Failed to share receipt')
            }), 500
    except Exception as e:
        logger.error(f"Error sharing receipt for user {current_user.id}: {str(e)}")
        return jsonify({
            'success': False,
            'message': trans('receipts_share_error', default='Error sharing receipt')
        }), 500
