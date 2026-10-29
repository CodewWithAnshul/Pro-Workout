// Account access and workout storage.
let currentUser=null;
let authMode='login';
async function request(path,body){
 const res=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
 const data=await res.json();if(!res.ok)throw Error(data.error||'Request failed');return data;
}
function messageAuth(m){document.getElementById('authMessage').textContent=m;}
function toggleAuthMode(){
 authMode=authMode==='login'?'signup':'login';
 document.getElementById('authHeading').textContent=authMode==='login'?'Welcome back':'Create your account';
 document.getElementById('authIntro').textContent=authMode==='login'?'Sign in to see your workout history.':'Your workouts are saved privately to your account.';
 document.getElementById('nameField').style.display=authMode==='signup'?'block':'none';
 document.getElementById('authPassword').autocomplete=authMode==='signup'?'new-password':'current-password';
 const passwordInput=document.getElementById('authPassword');
 if(authMode==='signup'){passwordInput.minLength=10;passwordInput.placeholder='At least 10 characters';}
 else{passwordInput.removeAttribute('minlength');passwordInput.placeholder='Enter your password';}
 document.getElementById('authSubmit').textContent=authMode==='login'?'Log in':'Create account';
 document.getElementById('authSwitch').textContent=authMode==='login'?'New here? Create an account':'Already registered? Log in';messageAuth('');
}
async function submitAuth(event){
 event.preventDefault();const btn=document.getElementById('authSubmit');btn.disabled=true;messageAuth('Checking account…');
 try{const user=(await request(authMode==='signup'?'signup':'login',{name:document.getElementById('authName').value.trim(),email:document.getElementById('authEmail').value.trim(),password:document.getElementById('authPassword').value})).user;document.getElementById('authPassword').value='';await openAccount(user);messageAuth('');}
 catch(e){messageAuth(e.message)}finally{btn.disabled=false}
}
async function openAccount(user){
 try{const data=await request('workouts');currentUser=user;records=data.records;const display=user.name||user.email.split('@')[0];
 document.getElementById('currentUserName').textContent=display;document.getElementById('currentUserEmail').textContent=user.email;
 document.getElementById('userAvatar').textContent=display.slice(0,2).toUpperCase();
 try{unit=localStorage.getItem(UNIT_KEY+'_'+user.id)==='lb'?'lb':'kg'}catch(e){unit='kg'}
 document.getElementById('authGate').classList.add('hidden');navigate('dashboard');}
 catch(e){messageAuth('Could not load your workouts: '+e.message)}
}
async function bootAuth(){try{const d=await request('me');if(d.user)await openAccount(d.user);}catch(e){messageAuth('Server connection failed: '+e.message)}}
async function signOutUser(){try{await request('logout',{});currentUser=null;records=[];document.getElementById('authGate').classList.remove('hidden');document.getElementById('authPassword').value='';messageAuth('Signed out.');}catch(e){notify(e.message)}}
async function cloudAdd(item){await request('workouts/add',{workout:item})}
async function cloudDelete(id){await request('workouts/delete',{id})}
async function cloudReplace(items){await request('workouts/replace',{records:items})}
