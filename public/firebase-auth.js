import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js';
import { getAuth, setPersistence, browserLocalPersistence, createUserWithEmailAndPassword, signInWithEmailAndPassword, sendEmailVerification, reload, updateProfile, RecaptchaVerifier, linkWithPhoneNumber, signInWithPhoneNumber, signOut, onAuthStateChanged } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js';

const config = window.FLIGHT_FRIEND_FIREBASE_CONFIG || {};
const configured = ['apiKey','authDomain','projectId','appId'].every(key => typeof config[key] === 'string' && config[key].trim() && !/PASTE|YOUR_PROJECT/i.test(config[key]));
const errorBox = () => document.getElementById('authError');
function show(message, error = false) {
  const box = errorBox();
  if (box) { box.textContent = message; box.hidden = false; box.classList.toggle('is-error', error); }
}
function clearMessage() { const box = errorBox(); if (box) { box.textContent = ''; box.hidden = true; box.classList.remove('is-error'); } }
function authApiError(data, fallback) { return new Error(data?.error || fallback); }
async function postWithToken(path, body, user) {
  const idToken = await user.getIdToken(true);
  const response = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'FlightFriend', 'Authorization': `Bearer ${idToken}` }, body: JSON.stringify(body) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw authApiError(data, 'Could not finish your account. Please try again.');
  return data;
}
let auth = null, firebaseUser = null, signupPhoneConfirmation = null, signupProfile = null, loginPhoneConfirmation = null, loginPhoneMode = false, loginCodeSent = false, signupVerifier = null, loginVerifier = null;
if (configured) {
  auth = getAuth(initializeApp(config));
  await setPersistence(auth, browserLocalPersistence);
  onAuthStateChanged(auth, async user => {
    firebaseUser = user;
    if (!user || !user.emailVerified || !user.phoneNumber) return;
    try { await postWithToken('/api/firebase/session', {}, user); if (window.refreshAccountState) await window.refreshAccountState(); }
    catch { /* A newly created account stays pending until its verified signup is completed. */ }
  });
}
function addAuthFields(form) {
  if (form.dataset.firebaseReady) return;
  form.dataset.firebaseReady = '1';
  const submit = form.querySelector('button[type="submit"]');
  const error = form.querySelector('#authError');
  if (!submit || !error) return;
  const isSignup = !!form.querySelector('[data-auth="signup"].active');
  if (isSignup) {
    const recaptcha = document.createElement('div'); recaptcha.id = 'firebaseSignupRecaptcha'; recaptcha.className = 'firebase-recaptcha';
    const codeWrap = document.createElement('div'); codeWrap.id = 'firebaseSignupCodeWrap'; codeWrap.hidden = true; codeWrap.innerHTML = '<label class="auth-label" for="firebaseSignupCode">SMS verification code</label><input class="auth-input" id="firebaseSignupCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="6-digit code"><small>Enter the code sent to your phone.</small>';
    error.before(recaptcha, codeWrap);
    if (!configured) { const note = document.createElement('p'); note.className='auth-note'; note.textContent='Real email and SMS verification is not connected yet. The Firebase project settings must be added before verified sign-in can work.'; error.before(note); }
  } else {
    const toggle = document.createElement('button'); toggle.type='button'; toggle.className='text-link firebase-phone-toggle'; toggle.textContent='Use a phone verification code instead';
    const recaptcha = document.createElement('div'); recaptcha.id='firebaseLoginRecaptcha'; recaptcha.className='firebase-recaptcha'; recaptcha.hidden=true;
    const codeWrap = document.createElement('div'); codeWrap.id='firebaseLoginCodeWrap'; codeWrap.hidden=true; codeWrap.innerHTML='<label class="auth-label" for="firebaseLoginCode">SMS verification code</label><input class="auth-input" id="firebaseLoginCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="6-digit code">';
    error.before(toggle, recaptcha, codeWrap);
    toggle.onclick=()=>{loginPhoneMode=!loginPhoneMode;loginCodeSent=false;loginPhoneConfirmation=null;toggle.textContent=loginPhoneMode?'Use email and password instead':'Use a phone verification code instead';const contact=form.querySelector('#authContact'),password=form.querySelector('#authPassword');contact.placeholder=loginPhoneMode?'+91… phone number':'Enter your registered email';password.hidden=loginPhoneMode;password.disabled=loginPhoneMode;password.required=!loginPhoneMode;recaptcha.hidden=!loginPhoneMode;codeWrap.hidden=true;submit.textContent=loginPhoneMode?'Send phone code ↗':'Log in ↗';clearMessage();};
    if (!configured) { toggle.hidden=true; const note=document.createElement('p');note.className='auth-note';note.textContent='Real sign-in is not connected yet. Add the Firebase project settings to enable verified email and phone access.';error.before(note); }
  }
}
const observer = new MutationObserver(() => { const form=document.getElementById('authForm'); if(form) addAuthFields(form); });
observer.observe(document.getElementById('modalContent') || document.body,{childList:true,subtree:true});

document.addEventListener('submit', async event => {
  if (event.target?.id !== 'authForm') return;
  const form=event.target, signup=!!form.querySelector('[data-auth="signup"].active');
  if (!configured) {
    if (location.protocol === 'file:' || location.protocol === 'https:') { event.preventDefault();event.stopImmediatePropagation();show(location.protocol === 'file:' ? 'This HTML preview has no account server. Real email and SMS verification needs the hosted Flight Friend site.' : 'Firebase is not connected yet. Add the project settings before creating or signing into a verified account.',true); }
    return;
  }
  event.preventDefault();event.stopImmediatePropagation();clearMessage();
  const submit=form.querySelector('[type="submit"]'); submit.disabled=true;
  try {
    if (signup) {
      if (!signupPhoneConfirmation) {
        const name=document.getElementById('signupName').value.trim(),email=document.getElementById('signupEmail').value.trim(),phone=document.getElementById('signupPhone').value.trim(),password=document.getElementById('signupPassword').value;
        signupProfile={name,email,phone,password,ageConfirmed:document.getElementById('ageConfirm').checked,termsConfirmed:document.getElementById('termsConfirm').checked,privacyConfirmed:document.getElementById('privacyConfirm').checked,safetyConfirmed:document.getElementById('safetyConfirm').checked,traveler:null};
        const opt=document.getElementById('listTraveler'); if(opt?.checked) signupProfile.traveler={from:document.getElementById('signupFrom').value,to:document.getElementById('signupTo').value,travelDate:document.getElementById('signupDate').value,flightNumber:document.getElementById('signupFlight').value.trim()};
        if(signupProfile.traveler && signupProfile.traveler.from===signupProfile.traveler.to) throw new Error('Choose two different airports.');
        const credential=await createUserWithEmailAndPassword(auth,email,password);await updateProfile(credential.user,{displayName:name});await sendEmailVerification(credential.user);
        if(!signupVerifier)signupVerifier=new RecaptchaVerifier(auth,'firebaseSignupRecaptcha',{size:'normal'});
        signupPhoneConfirmation=await linkWithPhoneNumber(credential.user,phone,signupVerifier);
        document.getElementById('firebaseSignupCodeWrap').hidden=false;submit.textContent='Verify phone & finish ↗';show('We emailed you a verification link and sent an SMS code. Enter the SMS code here; then verify the email before logging in.');
      } else {
        const code=document.getElementById('firebaseSignupCode').value.trim();if(!/^\d{6}$/.test(code))throw new Error('Enter the 6-digit SMS code.');
        const credential=await signupPhoneConfirmation.confirm(code);const result=await postWithToken('/api/firebase/register',signupProfile,credential.user);signupPhoneConfirmation=null;signupProfile=null;
        const doneMessage=result.pendingEmailVerification?'Phone verified. Check your email and follow the verification link. Then log in with your email and password.':'Your email and phone are verified. You can now log in.';form.innerHTML='<p class="auth-note">'+doneMessage+'</p><button type="button" class="btn btn-dark auth-submit" id="signupDone">Done</button>';document.getElementById('signupDone').onclick=()=>window.closeModal&&window.closeModal();return;
      }
    } else if (loginPhoneMode) {
      const phone=document.getElementById('authContact').value.trim();
      if (!loginCodeSent) {
        if(!loginVerifier)loginVerifier=new RecaptchaVerifier(auth,'firebaseLoginRecaptcha',{size:'normal'});
        loginPhoneConfirmation=await signInWithPhoneNumber(auth,phone,loginVerifier);loginCodeSent=true;document.getElementById('firebaseLoginCodeWrap').hidden=false;submit.textContent='Verify code & log in ↗';show('Enter the code sent by SMS.');
      } else {
        const code=document.getElementById('firebaseLoginCode').value.trim();if(!/^\d{6}$/.test(code))throw new Error('Enter the 6-digit SMS code.');const credential=await loginPhoneConfirmation.confirm(code);await finishLogin(credential.user);loginPhoneConfirmation=null;loginCodeSent=false;
      }
    } else {
      const email=document.getElementById('authContact').value.trim(),password=document.getElementById('authPassword').value;const credential=await signInWithEmailAndPassword(auth,email,password);await finishLogin(credential.user);
    }
  } catch(error) { show(error.message || 'Sign-in could not be completed. Please try again.',true);if(signupVerifier && error.code?.includes('captcha'))signupVerifier.clear(); }
  finally { submit.disabled=false; }
},true);
async function finishLogin(user) {
  await reload(user);
  if (!user.emailVerified) { await sendEmailVerification(user); throw new Error('Please verify the link we sent to your email before continuing. We sent it again.'); }
  if (!user.phoneNumber) throw new Error('This account has no verified phone number. Sign in by email, then finish phone verification.');
  await postWithToken('/api/firebase/session',{},user);
  if(window.refreshAccountState)await window.refreshAccountState();
  if(window.closeModal)window.closeModal();
  if(window.toastMessage)window.toastMessage('You are signed in with a verified email and phone.');
}

document.addEventListener('click',async event=>{const button=event.target.closest('#logoutButton');if(!button||!configured)return;event.preventDefault();event.stopImmediatePropagation();try{await signOut(auth);await fetch('/api/logout',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Requested-With':'FlightFriend'},body:'{}'});if(window.refreshAccountState)await window.refreshAccountState();if(window.toastMessage)window.toastMessage('You are logged out.');}catch(error){show(error.message||'Could not log out. Please try again.',true);}},true);

