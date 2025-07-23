from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
from bson import ObjectId
from datetime import datetime, timedelta
import logging
import io
import os
import requests
import re
import urllib.parse
import utils
from translations import trans
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from helpers.branding_helpers import draw_ficore_pdf_header, ficore_csv_header
import csv

logger = logging.getLogger(__name__)

# Placeholder functions for SMS/WhatsApp reminders (implement in utils.py or with external API)
def send_sms_reminder(recipient, message):
    """Placeholder for sending SMS reminder."""
    logger.info(f"Simulating SMS to {recipient}: {message}")
    return True, {'status': 'SMS sent successfully'}  # Replace with actual API call

def send_whatsapp_reminder(recipient, message):
    """Placeholder for sending WhatsApp reminder."""
    logger.info(f"Simulating WhatsApp to {recipient}: {message}")
    return True, {'status': 'WhatsApp sent successfully'}  # Replace with actual API call

class DebtorForm(FlaskForm):
    name = StringField(trans('debtors_debtor_name', default='Debtor Name'), validators=[DataRequired()])
    contact = StringField(trans('general_contact', default='Contact'), validators=[Optional()])
    amount_owed = FloatField(trans('debtors_amount_owed', default='Amount Owed'), validators=[DataRequired()])
    description = TextAreaField(trans('general_description', default='Description'), validators=[Optional()])
    submit = SubmitField(trans('debtors_add_debtor', default='Add Debtor'))

debtors_bp = Blueprint('debtors', __name__, url_prefix='/debtors')

@debtors_bp.route('/')
@login_required
@utils.requires_role('trader')
def index():
    """List all debtor records for the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'debtor'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'debtor'}
        debtors = list(db.records.find(query).sort('created_at', -1))
        
        return render_template(
            'debtors/index.html',
            debtors=debtors,
            title=trans('debtors_index', default='Debtors', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching debtors for user {current_user.id}: {str(e)}")
        flash(trans('debtors_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@debtors_bp.route('/manage')
@login_required
@utils.requires_role('trader')
def manage():
    """List all debtor records for management (edit/delete) by the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'debtor'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'debtor'}
        debtors = list(db.records.find(query).sort('created_at', -1))
        
        return render_template(
            'debtors/manage_debtors.html',
            debtors=debtors,
            title=trans('debtors_manage', default='Manage Debtors', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching debtors for manage page for user {current_user.id}: {str(e)}")
        flash(trans('debtors_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/view/<id>')
@login_required
@utils.requires_role('trader')
def view(id):
    """View detailed information about a specific debtor (JSON API)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            return jsonify({'error': trans('debtors_record_not_found', default='Record not found')}), 404
        
        debtor['_id'] = str(debtor['_id'])
        debtor['created_at'] = debtor['created_at'].isoformat() if debtor.get('created_at') else None
        debtor['reminder_count'] = debtor.get('reminder_count', 0)
        
        return jsonify(debtor)
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans('debtors_fetch_error', default='An error occurred')}), 500

@debtors_bp.route('/view_page/<id>')
@login_required
@utils.requires_role('trader')
def view_page(id):
    """Render a detailed view page for a specific debtor."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        
        return render_template(
            'debtors/view.html',
            debtor=debtor,
            title=trans('debtors_debt_details', default='Debt Details', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error rendering debtor view page {id} for user {current_user.id}: {str(e)}")
        flash(trans('debtors_view_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/share/<id>')
@login_required
@utils.requires_role('trader')
def share(id):
    """Generate a WhatsApp link to share IOU details."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            return jsonify({'success': False, 'message': trans('debtors_record_not_found', default='Record not found')}), 404
        if not debtor.get('contact'):
            return jsonify({'success': False, 'message': trans('debtors_no_contact', default='No contact provided for sharing')}), 400
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            return jsonify({'success': False, 'message': trans('debtors_insufficient_credits', default='Insufficient Ficore Credits to share IOU')}), 400
        
        contact = re.sub(r'\D', '', debtor['contact'])
        if contact.startswith('0'):
            contact = '234' + contact[1:]
        elif not contact.startswith('+'):
            contact = '234' + contact
        
        message = f"Hi {debtor['name']}, this is an IOU for {utils.format_currency(debtor['amount_owed'])} recorded on FiCore Records on {utils.format_date(debtor['created_at'])}. Details: {debtor.get('description', 'No description provided')}."
        whatsapp_link = f"https://wa.me/{contact}?text={urllib.parse.quote(message)}"
        
        if not utils.is_admin():
            user_query = utils.get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"IOU shared for {debtor['name']}"
            })
        
        return jsonify({'success': True, 'whatsapp_link': whatsapp_link})
    except Exception as e:
        logger.error(f"Error sharing IOU for debtor {id}: {str(e)}")
        return jsonify({'success': False, 'message': trans('debtors_share_error', default='An error occurred')}), 500

@debtors_bp.route('/send_reminder', methods=['POST'])
@login_required
@utils.requires_role('trader')
def send_reminder():
    """Send reminder to debtor via SMS/WhatsApp or set snooze."""
    try:
        data = request.get_json()
        debt_id = data.get('debtId')
        recipient = data.get('recipient')
        message = data.get('message')
        send_type = data.get('type', 'sms')
        snooze_days = data.get('snooze_days', 0)
        
        if not debt_id or (not recipient and not snooze_days):
            return jsonify({'success': False, 'message': trans('debtors_missing_fields', default='Missing required fields')}), 400
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(debt_id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(debt_id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            return jsonify({'success': False, 'message': trans('debtors_record_not_found', default='Record not found')}), 404
        
        credit_cost = 2 if recipient else 1
        if not utils.is_admin() and not utils.check_ficore_credit_balance(credit_cost):
            return jsonify({'success': False, 'message': trans('debtors_insufficient_credits', default='Insufficient Ficore Credits to send reminder')}), 400
        
        update_data = {'$inc': {'reminder_count': 1}}
        if snooze_days:
            update_data['$set'] = {'reminder_date': datetime.utcnow() + timedelta(days=snooze_days)}
        
        success = True
        api_response = {}
        
        if recipient:
            if send_type == 'sms':
                success, api_response = send_sms_reminder(recipient, message)
            elif send_type == 'whatsapp':
                success, api_response = send_whatsapp_reminder(recipient, message)
        
        if success:
            db.records.update_one({'_id': ObjectId(debt_id)}, update_data)
            
            if not utils.is_admin():
                user_query = utils.get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -credit_cost}})
                db.ficore_credit_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -credit_cost,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"{'Reminder sent' if recipient else 'Snooze set'} for {debtor['name']}"
                })
            
            db.reminder_logs.insert_one({
                'user_id': str(current_user.id),
                'debt_id': debt_id,
                'recipient': recipient or 'N/A',
                'message': message or 'Snooze',
                'type': send_type if recipient else 'snooze',
                'sent_at': datetime.utcnow(),
                'api_response': api_response if recipient else {'status': f'Snoozed for {snooze_days} days'}
            })
            
            return jsonify({'success': True, 'message': trans('debtors_reminder_sent' if recipient else 'debtors_snooze_set', default='Reminder sent successfully' if recipient else 'Snooze set successfully')})
        else:
            return jsonify({'success': False, 'message': trans('debtors_reminder_failed', default='Failed to send reminder'), 'details': api_response}), 500
            
    except Exception as e:
        logger.error(f"Error sending reminder: {str(e)}")
        return jsonify({'success': False, 'message': trans('debtors_reminder_error', default='An error occurred')}), 500

@debtors_bp.route('/generate_iou/<id>')
@login_required
@utils.requires_role('trader')
def generate_iou(id):
    """Generate PDF IOU for a debtor."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            flash(trans('debtors_insufficient_credits', default='Insufficient Ficore Credits to generate IOU'), 'danger')
            return redirect(url_for('agents_bp.manage_credits'))
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        draw_ficore_pdf_header(p, current_user, y_start=10.5)
        
        # Calculate the Y position for the title
        header_height = 0.7  # From draw_ficore_pdf_header
        extra_space = 0.2  # Additional space below the header
        title_y = 10.5 - header_height - extra_space
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, title_y * inch, trans('debtors_iou_title', default='FiCore Records - IOU'))
        
        p.setFont("Helvetica", 12)
        y_position = title_y - 0.5  # Start content below the title
        p.drawString(inch, y_position * inch, f"{trans('general_name', default='Debtor')}: {debtor['name']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_amount_owed', default='Amount Owed')}: {utils.format_currency(debtor['amount_owed'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('general_contact', default='Contact')}: {debtor.get('contact', 'N/A')}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('general_description', default='Description')}: {debtor.get('description', 'No description provided')}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_date_recorded', default='Date Recorded')}: {utils.format_date(debtor['created_at'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('debtors_reminders_sent', default='Reminders Sent')}: {debtor.get('reminder_count', 0)}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, trans('debtors_iou_footer', default='This document serves as an IOU recorded on FiCore Records.'))
        
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
                'ref': f"IOU generated for {debtor['name']}"
            })
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_IOU_{debtor["name"]}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating IOU for debtor {id}: {str(e)}")
        flash(trans('debtors_iou_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/generate_iou_csv/<id>')
@login_required
@utils.requires_role('trader')
def generate_iou_csv(id):
    """Generate CSV IOU for a debtor."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))
        
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            flash(trans('debtors_insufficient_credits', default='Insufficient Ficore Credits to generate IOU'), 'danger')
            return redirect(url_for('agents_bp.manage_credits'))
        
        output = []
        output.extend(ficore_csv_header(current_user))
        output.append([trans('debtors_iou_title', default='FiCore Records - IOU')])
        output.append([''])
        output.append([trans('general_name', default='Debtor'), debtor['name']])
        output.append([trans('debtors_amount_owed', default='Amount Owed'), utils.format_currency(debtor['amount_owed'])])
        output.append([trans('general_contact', default='Contact'), debtor.get('contact', 'N/A')])
        output.append([trans('general_description', default='Description'), debtor.get('description', 'No description provided')])
        output.append([trans('debtors_date_recorded', default='Date Recorded'), utils.format_date(debtor['created_at'])])
        output.append([trans('debtors_reminders_sent', default='Reminders Sent'), debtor.get('reminder_count', 0)])
        output.append([''])
        output.append([trans('debtors_iou_footer', default='This document serves as an IOU recorded on FiCore Records.')])
        
        if not utils.is_admin():
            user_query = utils.get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"IOU CSV generated for {debtor['name']}"
            })
        
        buffer = io.BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        
        return Response(
            buffer,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_IOU_{debtor["name"]}.csv'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating IOU CSV for debtor {id}: {str(e)}")
        flash(trans('debtors_iou_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role('trader')
def add():
    """Add a new debtor record."""
    form = DebtorForm()
    if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
        flash(trans('debtors_insufficient_credits', default='Insufficient Ficore Credits to add debtor'), 'danger')
        return redirect(url_for('agents_bp.manage_credits'))

    if form.validate_on_submit():
        try:
            db = utils.get_mongo_db()
            debtor_data = {
                'user_id': str(current_user.id),
                'type': 'debtor',
                'name': form.name.data,
                'contact': form.contact.data,
                'amount_owed': form.amount_owed.data,
                'description': form.description.data,
                'created_at': datetime.utcnow(),
                'reminder_count': 0
            }
            db.records.insert_one(debtor_data)
            
            if not utils.is_admin():
                user_query = utils.get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
                db.ficore_credit_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -1,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Debtor added: {form.name.data}"
                })
            
            flash(trans('debtors_add_success', default='Debtor added successfully'), 'success')
            return redirect(url_for('debtors.index'))
        except Exception as e:
            logger.error(f"Error adding debtor for user {current_user.id}: {str(e)}")
            flash(trans('debtors_add_error', default='An error occurred while adding debtor'), 'danger')

    return render_template(
        'debtors/add.html',
        form=form,
        title=trans('debtors_add_debtor', default='Add Debtor', lang=session.get('lang', 'en'))
    )

@debtors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('trader')
def edit(id):
    """Edit an existing debtor record."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        
        if not debtor:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors.index'))

        form = DebtorForm(data={
            'name': debtor['name'],
            'contact': debtor.get('contact', ''),
            'amount_owed': debtor['amount_owed'],
            'description': debtor.get('description', '')
        })

        if form.validate_on_submit():
            try:
                updated_record = {
                    'name': form.name.data,
                    'contact': form.contact.data,
                    'amount_owed': form.amount_owed.data,
                    'description': form.description.data,
                    'updated_at': datetime.utcnow()
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                flash(trans('debtors_edit_success', default='Debtor updated successfully'), 'success')
                return redirect(url_for('debtors.index'))
            except Exception as e:
                logger.error(f"Error updating debtor {id} for user {current_user.id}: {str(e)}")
                flash(trans('debtors_edit_error', default='An error occurred'), 'danger')

        return render_template(
            'debtors/edit.html',
            form=form,
            debtor=debtor,
            title=trans('debtors_edit_debtor', default='Edit Debtor', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role('trader')
def delete(id):
    """Delete a debtor record."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'debtor'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            flash(trans('debtors_delete_success', default='Debtor deleted successfully'), 'success')
        else:
            flash(trans('debtors_record_not_found', default='Record not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans('debtors_delete_error', default='An error occurred'), 'danger')
    return redirect(url_for('debtors.index'))
