require('dotenv').config();
const {createClient}=require('@supabase/supabase-js');
const manifest=require('./secl-area-project-manifest.json');
const normalize=v=>String(v||'').normalize('NFKC').trim().replace(/\\s+/g,' ').toLocaleLowerCase('en-IN');
const aliases=new Map([['bisrampur','bishrampur'],['jamuna kotma','jamuna & kotma'],['cws korba','korba']]);
async function main(){
 if(!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_KEY) throw new Error('SUPABASE_URL and backend-only SUPABASE_SERVICE_KEY are required');
 const apply=process.argv.includes('--apply');
 const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_KEY);
 const expectedProjects=manifest.areas.reduce((n,a)=>n+a.projects.length,0);
 const report={mode:apply?'apply':'dry-run',expectedAreas:13,expectedProjects:79,insertedAreas:0,matchedAreas:0,insertedProjects:0,matchedProjects:0,conflicts:[],errors:[]};
 if(manifest.areas.length!==13||expectedProjects!==79) throw new Error('Manifest count mismatch: '+manifest.areas.length+' Areas, '+expectedProjects+' projects');
 const {data:areas,error:ae}=await db.from('areas').select('id,name,normalized_name,source_label');
 if(ae) throw new Error('Cannot inspect areas: '+ae.message);
 const areaMap=new Map();
 for(const a of areas||[]){const k=normalize(a.normalized_name||a.name);if(areaMap.has(k))report.conflicts.push({type:'duplicate-area',key:k,ids:[areaMap.get(k).id,a.id]});else areaMap.set(k,a);}
 const resolved=new Map();
 for(const a of manifest.areas){
  const key=normalize(a.name);let found=areaMap.get(key);
  for(const [alias,target] of aliases) if(target===key&&!found&&areaMap.has(alias)) report.conflicts.push({type:'area-alias-conflict',source:alias,canonical:a.name,id:areaMap.get(alias).id,action:'manual reconciliation required; no automatic rename/delete'});
  if(!found&&apply){const {data,error}=await db.from('areas').insert({name:a.name,normalized_name:key,source_label:(a.sourceLabels||[])[0]||null}).select('id,name,normalized_name').single();if(error){report.errors.push({type:'insert-area',name:a.name,message:error.message});continue;}found=data;areaMap.set(key,found);report.insertedAreas++;}
  else if(found)report.matchedAreas++;
  if(found)resolved.set(a.name,found);
 }
 const {data:mines,error:me}=await db.from('mines').select('id,area_id,name,normalized_name,source_label,source_area_label');
 if(me) throw new Error('Cannot inspect mines: '+me.message);
 const byKey=new Map();
 for(const m of mines||[]){const k=m.area_id+':'+normalize(m.normalized_name||m.name);if(byKey.has(k))report.conflicts.push({type:'duplicate-project',key:k,ids:[byKey.get(k).id,m.id]});else byKey.set(k,m);}
 for(const a of manifest.areas){
  const parent=resolved.get(a.name);if(!parent){report.errors.push({type:'unresolved-area',area:a.name});continue;}
  for(const name of a.projects){
   const key=parent.id+':'+normalize(name);const existing=byKey.get(key);
   if(existing){report.matchedProjects++;if(existing.name!==name)report.conflicts.push({type:'project-name-differs',area:a.name,expected:name,existing:existing.name,id:existing.id});continue;}
   const elsewhere=(mines||[]).filter(m=>normalize(m.name)===normalize(name)&&m.area_id!==parent.id);
   if(elsewhere.length){report.conflicts.push({type:'project-parent-conflict',area:a.name,project:name,existing:elsewhere.map(m=>({id:m.id,area_id:m.area_id}))});continue;}
   if(apply){const {data,error}=await db.from('mines').insert({area_id:parent.id,name,normalized_name:normalize(name),source_label:name,source_area_label:(a.sourceLabels||[])[0]||a.name}).select('id,area_id,name,normalized_name').single();if(error){report.errors.push({type:'insert-project',area:a.name,project:name,message:error.message});continue;}byKey.set(key,data);report.insertedProjects++;}
  }
 }
 const [{data:finalAreas,error:fae},{data:finalMines,error:fme}]=await Promise.all([db.from('areas').select('id,name,normalized_name'),db.from('mines').select('id,area_id,name,normalized_name')]);
 if(fae)report.errors.push({type:'verify-areas',message:fae.message});if(fme)report.errors.push({type:'verify-projects',message:fme.message});
 report.finalAreaRows=finalAreas?.length??null;report.canonicalAreasPresent=manifest.areas.filter(a=>(finalAreas||[]).some(x=>normalize(x.name)===normalize(a.name))).length;
 report.finalProjectRows=finalMines?.length??null;
 report.manifestProjectsPresent=manifest.areas.reduce((n,a)=>{const parent=(finalAreas||[]).find(x=>normalize(x.name)===normalize(a.name));return n+(parent?a.projects.filter(name=>(finalMines||[]).some(m=>m.area_id===parent.id&&normalize(m.name)===normalize(name))).length:0);},0);
 const korba=(finalAreas||[]).find(a=>normalize(a.name)==='korba');
 report.centralWorkshopUnderKorba=!!korba&&(finalMines||[]).some(m=>m.area_id===korba.id&&normalize(m.name)==='central workshop');
 report.separateCwsKorbaArea=(finalAreas||[]).some(a=>normalize(a.name)==='cws korba');
 report.success=report.canonicalAreasPresent===13&&report.manifestProjectsPresent===79&&report.centralWorkshopUnderKorba&&!report.separateCwsKorbaArea&&report.conflicts.length===0&&report.errors.length===0;
 console.log(JSON.stringify(report,null,2));if(!report.success)process.exitCode=2;
}
main().catch(e=>{console.error('Seed failed:',e.message);process.exitCode=1;});
