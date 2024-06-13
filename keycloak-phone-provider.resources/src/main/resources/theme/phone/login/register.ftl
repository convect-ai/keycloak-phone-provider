<div class="card-pf">
    <div class="card-pf-body">
        <form id="kc-register-form" onsubmit="return checkForm()" action="${url.registrationAction}" method="post">
            <div class="form-group">
                <label for="credentialType">选择注册方式</label>
                <select id="credentialType" name="credentialType" class="form-control" required>
                    <option value="">请选择</option>
                    <option value="phone">手机注册</option>
                    <option value="email">邮箱注册</option>
                </select>
            </div>
            <div id="phone-fields" style="display:none;">
                <div class="form-group">
                    <label for="areaCode">区号</label>
                    <input type="text" id="areaCode" name="areaCode" class="form-control" placeholder="区号" />
                </div>
                <div class="form-group">
                    <label for="phoneNumber">手机号</label>
                    <input type="text" id="phoneNumber" name="phoneNumber" class="form-control" placeholder="手机号" />
                </div>
                <div class="form-group">
                    <label for="smsCode">验证码</label>
                    <div class="input-group">
                        <input type="text" id="smsCode" name="smsCode" class="form-control"
                               placeholder="验证码" />
                        <div class="input-group-append">
                            <button type="button" class="btn btn-primary" id="getVerificationCode">获取验证码</button>
                        </div>
                    </div>
                </div>
            </div>
            <div id="email-fields" style="display:none;">
                <div class="form-group">
                    <label for="email">邮箱</label>
                    <input type="email" id="email" name="email" class="form-control" placeholder="邮箱" />
                </div>
                <div class="form-group">
                    <label for="password">密码</label>
                    <input type="password" id="password" name="password" class="form-control" placeholder="密码" />
                </div>
                <div class="form-group">
                    <label for="passwordConfirm">确认密码</label>
                    <input type="password" id="password-confirm" name="password-confirm" class="form-control"
                           placeholder="确认密码" />
                </div>
            </div>
            <button type="submit" class="btn btn-primary btn-block">注册</button>
        </form>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>

<script>
  document.getElementById('credentialType').addEventListener('change', function () {
    var credentialType = this.value;
    if (credentialType === 'phone') {
      document.getElementById('phone-fields').style.display = 'block';
      document.getElementById('email-fields').style.display = 'none';
    } else if (credentialType === 'email') {
      document.getElementById('phone-fields').style.display = 'none';
      document.getElementById('email-fields').style.display = 'block';
    } else {
      document.getElementById('phone-fields').style.display = 'none';
      document.getElementById('email-fields').style.display = 'none';
    }
  });

  document.getElementById('getVerificationCode').addEventListener('click', function () {
    var areaCode = document.getElementById('areaCode').value;
    var phoneNumber = document.getElementById('phoneNumber').value;
    if (!areaCode || !phoneNumber) {
      alert('请输入区号和手机号');
      return;
    }
    // 调用发送验证码的 API，需要实现相应的服务端逻辑
    sendVerificationCode();
  });

  function req(phoneNumber) {
    const params = { params: { phoneNumber } }
    axios.get(window.location.origin + '/realms/${realm.name}/sms/registration-code', params)
      .then(res => app.disableSend(res.data.expires_in))
      .catch(e => app.errorMessage = e.response.data.error);
  }

  function sendVerificationCode() {
    var phoneNumber = document.getElementById('phoneNumber').value;

    var verificationCodeBtn = document.getElementById('getVerificationCode');

    verificationCodeBtn.disabled = true;  // Disable button to prevent multiple requests

    req(phoneNumber);

    function checkForm() {
      var credentialType = document.getElementById('credentialType').value;
      if (credentialType === 'phone') {
        var phoneNumber = document.getElementById('phoneNumber').value;
        var verificationCode = document.getElementById('smsCode').value;
        if (!phoneNumber || !verificationCode) {
          alert('请输入手机号和验证码');
          return false;
        }
      } else if (credentialType === 'email') {
        var email = document.getElementById('email').value;
        var password = document.getElementById('password').value;
        var passwordConfirm = document.getElementById('password-confirm').value;
        if (!email || !password || !passwordConfirm) {
          alert('请输入邮箱和密码');
          return false;
        }
        if (password !== passwordConfirm) {
          alert('密码和确认密码不一致');
          return false;
        }
      } else {
        alert('请选择注册方式');
        return false;
      }
      return true;
    }
  }
</script>
