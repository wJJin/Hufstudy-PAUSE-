from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views.generic.base import TemplateView
from .decorators import *
from .models import User 
from django.views.generic import View
from django.contrib import messages
from django.conf import settings

from django.urls import reverse
from .helper import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

# 약관 및 개인정보 동의
@method_decorator(logout_message_required, name='dispatch')
class AgreementView(View):
    def get(self, request, *args, **kwargs):
        request.session['agreement'] = False
        return render(request, 'users/agreement.html')

    def post(self, request, *args, **kwarg):
        if request.POST.get('agreement1', False) and request.POST.get('agreement2', False):
            request.session['agreement'] = True

            if request.POST.get('register') == 'register':       
                return redirect('/register/')
            else:
                return redirect('/register/')
        else:
            messages.info(request, "약관에 모두 동의해주세요.")
            return render(request, 'users/agreement.html')

# 회원가입
from django.core.exceptions import PermissionDenied, ValidationError
from .forms import RegisterForm
from django.views.generic import CreateView
class RegisterView(CreateView):
    model = User
    template_name = 'users/register.html'
    form_class = RegisterForm

    def get(self, request, *args, **kwargs):
        if not request.session.get('agreement', False):
            raise PermissionDenied
        request.session['agreement'] = False
        return super().get(request, *args, **kwargs)

    def get_success_url(self):
        self.request.session['register_auth'] = True
        messages.success(self.request, '회원님의 입력한 Email 주소로 인증 메일이 발송되었습니다. 인증 후 로그인이 가능합니다.')
        return reverse('users:register_success')

    def form_valid(self, form):
        self.object = form.save()

        send_mail(
            '[HUFSTUDY] HUFSTUDY 웹사이트 회원가입 인증메일',
            [self.object.email],
            html=render_to_string('users/register_email.html', {
                'user': self.object,
                'uid': urlsafe_base64_encode(force_bytes(self.object.pk)).encode().decode(),
                'domain': self.request.META['HTTP_HOST'],
                'token': default_token_generator.make_token(self.object),
            }),
        )
        return redirect(self.get_success_url())

def activate(request, uid64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uid64))
        current_user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
        messages.error(request, '메일 인증에 실패했습니다.')
        return redirect('users:login')

    if default_token_generator.check_token(current_user, token):
        current_user.is_active = True
        current_user.save()

        messages.info(request, '메일 인증이 완료 되었습니다. 회원가입을 축하드립니다!')
        return redirect('users:login')

    messages.error(request, '메일 인증에 실패했습니다.')
    return redirect('users:login')

def register_success(request):
    if not request.session.get('register_auth', False):
        raise PermissionDenied
    request.session['register_auth'] = False

    return render(request, 'users/register_success.html')

# 로그인
from .forms import LoginForm
from django.contrib.auth import login, authenticate
from django.views.generic import FormView
from notice.models import Notice

class LoginView(FormView):
    
    template_name = 'users/home.html'
    form_class = LoginForm
    success_url = '/'

    def form_valid(self, form):
        user_id = form.cleaned_data.get("user_id")
        password = form.cleaned_data.get("password")
        user = authenticate(self.request, username=user_id, password=password)
        
        if user is not None:
            self.request.session['user_id'] = user_id
            login(self.request, user)

        return super().form_valid(form)
    
def main_view(request):
    notice_list = Notice.objects.order_by('-id')[:5]
    context = {
        'notice_list' : notice_list,
    }
    return render(request, 'users/home.html', context)


# 로그아웃
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect('/')

# 마이페이지


@login_message_required
def mypage_view(request):
    if request.method == 'GET':
        return render(request, 'users/mypage.html')





from .forms import CustomUserChangeForm

@login_message_required
def mypage_update_view(request):
    if request.method == 'POST':
        user_change_form = CustomUserChangeForm(request.POST, instance=request.user)

        if user_change_form.is_valid():
            user_change_form.save()
            messages.success(request, '회원정보가 수정되었습니다.')
            return render(request, 'users/mypage.html')

    else:
        user_change_form = CustomUserChangeForm(instance = request.user)

        return render(request, 'users/mypage_update.html', {'user_change_form':user_change_form})
       
#회원탈퇴

from .forms import CheckPasswordForm

@login_message_required
def mypage_delete_view(request):
    if request.method == 'POST':
        password_form = CheckPasswordForm(request.user, request.POST)
        
        if password_form.is_valid():
            request.user.delete()
            logout(request)
            messages.success(request, "회원탈퇴가 완료되었습니다.")
            return redirect('/')
    else:
        password_form = CheckPasswordForm(request.user)

    return render(request, 'users/mypage_delete.html', {'password_form':password_form})


#비밀번호 변경

from .forms import CustomPasswordChangeForm
from django.contrib.auth import update_session_auth_hash

@login_message_required
def password_edit_view(request):
    if request.method == 'POST':
        password_change_form = CustomPasswordChangeForm(request.user, request.POST)
        if password_change_form.is_valid():
            user = password_change_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "비밀번호가 변경되었습니다.")
            return redirect('users:mypage')
    else:
        password_change_form = CustomPasswordChangeForm(request.user)

    return render(request, 'users/mypage_password.html', {'password_change_form':password_change_form})
