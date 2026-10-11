document.addEventListener('DOMContentLoaded',()=>{
 const btn=document.getElementById('menuToggle');
 if(btn)btn.addEventListener('click',()=>document.getElementById('sidebar')?.classList.toggle('open'));
 const safeConfirm=(msg)=>{try{return window.confirm(msg)}catch(e){return true}};
 const safeAlert=(msg)=>{try{window.alert(msg)}catch(e){console.warn(msg)}};
 document.querySelectorAll('[data-confirm]').forEach(form=>form.addEventListener('submit',e=>{if(!safeConfirm(form.dataset.confirm))e.preventDefault()}));
 document.querySelectorAll('[data-table-filter]').forEach(input=>input.addEventListener('input',()=>{
   const table=document.getElementById(input.dataset.tableFilter);const query=input.value.trim().toLowerCase();
   if(table)table.querySelectorAll('tbody tr').forEach(tr=>{tr.hidden=!tr.textContent.toLowerCase().includes(query)})
 }));
 const files=document.getElementById('photos');if(files)files.addEventListener('change',()=>{
   if(files.files.length>3){safeAlert('Select at most three images.');files.value='';return}
   for(const f of files.files){if(f.size>5*1024*1024){safeAlert('Each image must be 5 MB or smaller.');files.value='';return}}
 });
 const newForm=document.getElementById('newComplaintForm');if(newForm)newForm.addEventListener('submit',()=>{
    const btn=document.getElementById('submitBtn');if(btn){btn.disabled=true;btn.textContent='Submitting...'}
 });
});
