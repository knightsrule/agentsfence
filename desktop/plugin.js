import { host, useValue } from '@hermes/plugin-sdk'
import { createElement as h, useEffect, useState } from 'react'

const colors = {active:'var(--ui-accent)',ready:'var(--ui-text-secondary)',enabled:'var(--ui-text-secondary)',compiling:'#c58a20',fallback:'#c58a20',inactive:'#cf5959',restart_required:'#c58a20',blocked:'#cf5959',expired:'#c58a20',unknown:'var(--ui-text-tertiary)'}
const labels = {active:'Active',ready:'Ready · no task policy',enabled:'Enabled · loads when Hermes starts',compiling:'Compiling policy · tools blocked',fallback:'Fallback · read-only',inactive:'Not protected',restart_required:'Restart required',blocked:'Tools blocked · repair required',expired:'Policy expired',unknown:'Status unavailable'}
const enforcement = {ok:'PROTECTED',problem:'NOT PROTECTED',unverified:'UNVERIFIED'}
const box = {border:'1px solid var(--ui-stroke-secondary)',borderRadius:10,padding:14,marginBottom:14}
const button = {border:'1px solid var(--ui-stroke-secondary)',borderRadius:6,padding:'7px 11px',cursor:'pointer',background:'var(--ui-bg-secondary)',color:'var(--ui-text-primary)'}
const field = {...button,width:'100%',boxSizing:'border-box',marginTop:7}
const primary = {...button,background:'var(--ui-accent)',color:'#fff',width:'100%'}
const link = {background:'none',border:0,padding:'6px 0',cursor:'pointer',color:'var(--ui-accent)',fontSize:12}
const muted = {fontSize:12,color:'var(--ui-text-secondary)'}
const LONG = {timeoutMs:900000}  // protect builds Hermes' environment; a test compiles several requests

function useStatus(ctx) {
  const profile = useValue(host.state.profile)
  const focusedProfile = useValue(host.state.focusedSessionProfile || host.state.profile)
  const session = useValue(host.state.focusedStoredSessionId || host.state.focusedSessionId || host.state.activeSessionId)
  const owner = useValue(host.state.focusedSessionOwner || host.state.profile)
  const connection = useValue(host.state.connectionId || host.state.profile)
  const gateway = useValue(host.state.gateway)
  const [data,setData] = useState(null)
  const [error,setError] = useState('')
  const [revision,setRevision] = useState(0)
  useEffect(() => {
    let stopped = false
    setData(null)
    const refresh = async () => {
      if ((focusedProfile && profile !== focusedProfile) ||
          (session && host.state.focusedSessionOwner && (!owner || owner.profile !== profile || owner.connectionId !== (connection || 'local')))) {
        setData(null); setError('Select the focused chat’s backend and profile to view its protection status.'); return
      }
      try {
        const result = await ctx.rest('/status' + (session ? '?session_id='+encodeURIComponent(session) : ''))
        if (!stopped) { setData(result); setError('') }
      } catch (_) {
        if (!stopped) { setData(null); setError('AgentsFence is not running in this profile’s backend. Protect the profile, then restart its backend.') }
      }
    }
    refresh()
    const timer = setInterval(refresh,5000)
    const off = host.onEvent('plugin.agentsfence.status.changed', refresh)
    return () => { stopped=true; clearInterval(timer); off() }
  },[ctx,profile,focusedProfile,session,gateway,owner,connection,revision])
  return {data,error,session,profile,refresh:()=>setRevision(value=>value+1)}
}

function Chip({ctx,open}) {
  const {data,error,profile} = useStatus(ctx)
  const state = data?.state || 'unknown'
  useEffect(() => {
    if (state === 'fallback') host.notify({kind:'warning',title:'AgentsFence fallback',message:'Policy compilation failed in '+profile+'. Tools are read-only until it recovers. Open AgentsFence for details.'})
  },[state,profile])
  return h('button',{onClick:open,title:error || 'AgentsFence protection status',style:{color:colors[state],fontSize:11,padding:'0 8px'}},'◈ Fence · '+labels[state])
}

function Lines({lines}) {
  return lines?.length ? h('pre',{role:'status',style:{whiteSpace:'pre-wrap',fontFamily:'inherit',lineHeight:1.6,margin:'10px 0'}},lines.join('\n')) : null
}

async function recycle(ctx,names,setMessage) {
  if(!names.length) return true
  if(!window.hermesDesktop?.recycleBackend) {
    setMessage('Restart Hermes Desktop (quit with Cmd+Q and reopen) so '+names.join(', ')+' load the change.'); return false
  }
  for(const name of names) {setMessage('Restarting '+name+'…'); await window.hermesDesktop.recycleBackend(name)}
  for(let attempt=0;attempt<10;attempt++) {
    try {await ctx.rest('/status');setMessage('');return true} catch(_) {await new Promise(resolve=>setTimeout(resolve,1000))}
  }
  setMessage('Hermes is still reconnecting. Check the overview when it is connected.')
  return false
}

function Profiles({ctx,profile,onChanged}) {
  const [rows,setRows] = useState([])
  const [includeNew,setIncludeNew] = useState(false)
  const [busy,setBusy] = useState('')
  const [lines,setLines] = useState([])
  const [message,setMessage] = useState('')
  async function load() {
    try {const r=await ctx.rest('/profiles');setRows(r.profiles);setIncludeNew(r.include_new)} catch(e) {setMessage(String(e.message || e))}
  }
  useEffect(()=>{load()},[ctx,profile])
  async function change(path,names,extra={}) {
    setBusy(names.join(', '));setMessage('');setLines([])
    try {
      const r=await ctx.rest(path,{method:'POST',body:{profiles:names,...extra},...LONG})
      setLines(r.lines||[])
      await recycle(ctx,r.restart||[],setMessage)
      await load();onChanged()
    } catch(e) {setMessage(String(e.message || e))} finally {setBusy('')}
  }
  async function toggleNew(value) {
    setIncludeNew(value);setBusy('updating profiles');setMessage('')
    try {await ctx.rest('/include-new',{method:'POST',body:{include_new:value}})}
    catch(e) {setIncludeNew(!value);setMessage(String(e.message || e))}
    finally {setBusy('')}
  }
  const unprotected=rows.filter(r=>!r.protected&&!r.error).map(r=>r.name)
  return h('section',{style:box},
    h('h3',{style:{fontWeight:600,marginBottom:6}},'Profiles'),
    h('p',{style:muted},'Protecting a profile enables AgentsFence there and builds Hermes’ environment with it. A failure changes nothing.'),
    ...rows.map(r=>h('div',{key:r.name,style:{display:'flex',alignItems:'center',justifyContent:'space-between',gap:8,padding:'10px 0',borderBottom:'1px solid var(--ui-stroke-secondary)'}},
      h('div',null,h('strong',null,r.name+(r.name===profile?' (this backend)':'')),
        h('div',{style:muted},r.error?'Cannot read this profile: '+r.error:(r.protected?(enforcement[r.overall]||'Protected')+' · compiler '+r.compiler.model:'Not protected'))),
      !r.error && h('button',{style:button,disabled:!!busy,onClick:()=>change(r.protected?'/unprotect':'/protect',[r.name])},busy.includes(r.name)?'Working…':r.protected?'Unprotect':'Protect'))),
    unprotected.length>1 && h('button',{style:{...primary,marginTop:12},disabled:!!busy,onClick:()=>change('/protect',unprotected)},busy?'Working…':'Protect all ('+unprotected.length+')'),
    h('label',{style:{display:'block',marginTop:12}},h('input',{type:'checkbox',checked:includeNew,disabled:!!busy,onChange:e=>toggleNew(e.target.checked)}),' Protect new profiles automatically'),
    h('p',{style:muted},'New profiles are protected the next time AgentsFence runs (this pane opening, or any agentsfence command). Profiles you unprotect stay unprotected.'),
    h(Lines,{lines}),
    message && h('p',{role:'alert',style:{whiteSpace:'pre-wrap',marginTop:10}},message))
}

function Settings({ctx,profile,onDone}) {
  const [row,setRow] = useState(null)
  const [mode,setMode] = useState('inherit')
  const [model,setModel] = useState('')
  const [provider,setProvider] = useState('auto')
  const [budget,setBudget] = useState(30)
  const [strict,setStrict] = useState(false)
  const [retention,setRetention] = useState(90)
  const [busy,setBusy] = useState(false)
  const [lines,setLines] = useState([])
  const [message,setMessage] = useState('')
  useEffect(()=>{(async()=>{
    try {
      const r=await ctx.rest('/profiles')
      const mine=r.profiles.find(p=>p.name===profile)||r.profiles[0]
      setRow(mine)
      if(mine?.settings) {const s=mine.settings;setMode(s.mode);setModel(s.mode==='selected'?s.model:'');setProvider(s.provider||'auto');setBudget(s.compile_budget);setStrict(s.strict_yolo);setRetention(s.retention_days)}
    } catch(e) {setMessage(String(e.message || e))}
  })()},[ctx,profile])
  async function save() {
    setBusy(true);setMessage('');setLines([])
    const body={apply_to_all_profiles:true,compile_budget:Number(budget),strict_yolo:strict,retention_days:Number(retention)}
    if(mode==='selected') {body.model=model.trim();body.provider=provider||'auto'} else body.mode='inherit'
    try {const r=await ctx.rest('/settings',{method:'POST',body,...LONG});setLines(r.lines||[])} catch(e) {setMessage(String(e.message || e))} finally {setBusy(false)}
  }
  const choices=(row?.models||[]).filter(m=>m.model)
  return h('section',{style:box},
    h('h3',{style:{fontWeight:600,marginBottom:6}},'Settings · every protected profile'),
    h('h4',{style:{fontWeight:600,margin:'12px 0 4px'}},'Compiler'),
    h('p',{style:muted},'The compiler turns your request into permissions. Your chat model does the task.'),
    h('select',{style:field,disabled:busy,value:mode,onChange:e=>setMode(e.target.value)},
      h('option',{value:'inherit'},'Each profile’s default model (a chat’s -m never changes it)'),
      h('option',{value:'selected'},'A dedicated compiler model')),
    mode==='selected' && h('div',null,
      h('select',{style:field,disabled:busy,value:'',onChange:e=>{if(e.target.value==='')return;const c=choices[Number(e.target.value)];setModel(c.model);setProvider(c.provider)}},
        h('option',{value:''},'Pick a model this profile already uses…'),...choices.map((c,i)=>h('option',{key:i,value:String(i)},c.label+' · '+c.model))),
      h('input',{style:field,disabled:busy,value:model,onChange:e=>setModel(e.target.value),placeholder:'Model identifier'}),
      h('input',{style:field,disabled:busy,value:provider,onChange:e=>setProvider(e.target.value),placeholder:'Hermes provider (auto)'})),
    h('label',{style:{display:'block',marginTop:10}},'Compile budget (seconds)',h('input',{style:field,type:'number',min:1,max:480,disabled:busy,value:budget,onChange:e=>setBudget(e.target.value)})),
    h('p',{style:muted},'A compile that runs out of time falls back to read-only. Raising this also raises Hermes’ plugin hook timeout to match. A faster model is usually the better fix.'),
    h('h4',{style:{fontWeight:600,margin:'14px 0 4px'}},'Monitoring'),
    h('label',{style:{display:'block'}},h('input',{type:'checkbox',disabled:busy,checked:strict,onChange:e=>setStrict(e.target.checked)}),' Block instead of auto-approving when approvals are off or --yolo is on'),
    h('p',{style:muted},'Approvals stay Hermes’ own: it asks you in its approval dialog, and AgentsFence never answers for you.'),
    h('label',{style:{display:'block',marginTop:10}},'Keep rotated audit logs (days)',h('input',{style:field,type:'number',min:1,disabled:busy,value:retention,onChange:e=>setRetention(e.target.value)})),
    h(Lines,{lines}),
    message && h('p',{role:'alert',style:{whiteSpace:'pre-wrap',marginTop:10}},message),
    h('button',{style:{...primary,marginTop:14},disabled:busy||(mode==='selected'&&!model.trim()),onClick:save},busy?'Saving…':'Save'),
    h('button',{style:link,disabled:busy,onClick:onDone},'Back to overview'))
}

function Test({ctx,profile,onDone}) {
  const [live,setLive] = useState(true)
  const [busy,setBusy] = useState(false)
  const [confirm,setConfirm] = useState(null)
  const [report,setReport] = useState('')
  const [message,setMessage] = useState('')
  const [runId,setRunId] = useState(null)
  const [progress,setProgress] = useState(null)
  const [elapsed,setElapsed] = useState(0)
  useEffect(()=>{
    if(!runId)return
    let active=true, timer
    const began=Date.now()
    const clock=setInterval(()=>setElapsed(Math.floor((Date.now()-began)/1000)),1000)
    async function poll() {
      try {
        const state=await ctx.rest('/test-progress/'+encodeURIComponent(runId)+'?profile='+encodeURIComponent(profile))
        if(active)setProgress(state)
      } catch(_) { /* The POST may not have registered this run yet. */ }
      finally {if(active)timer=setTimeout(poll,1000)}
    }
    poll()
    return ()=>{active=false;clearTimeout(timer);clearInterval(clock)}
  },[ctx,profile,runId])
  async function run(extra={}) {
    const id=crypto.randomUUID()
    setBusy(true);setMessage('');setReport('');setConfirm(null);setProgress(null);setElapsed(0);setRunId(id)
    try {
      const r=await ctx.rest('/test',{method:'POST',body:{profile,live,...extra,run_id:id},...LONG})
      if(r.needs_confirmation) setConfirm(r.live)
      else setReport(r.report || r.error || 'No result.')
    } catch(e) {setMessage(String(e.message || e))} finally {setBusy(false);setRunId(null)}
  }
  return h('section',{style:box},
    h('h3',{style:{fontWeight:600,marginBottom:6}},'Test '+profile),
    h('p',null,'Runs the six scenarios in this profile: an injected send blocked, an authorized email allowed, a single send approved, and more. Every compile is fresh; nothing touches your real mail or files.'),
    h('label',{style:{display:'block',marginTop:10}},h('input',{type:'checkbox',disabled:busy,checked:live,onChange:e=>setLive(e.target.checked)}),' Also let a weak chat model try the scenarios (a free model when available)'),
    busy && h('div',{role:'status','aria-live':'polite',style:{margin:'12px 0',lineHeight:1.6}},
      h('p',null,progress?.message || 'Waiting for Hermes to start this test…'),
      h('p',{style:muted},(progress?.total != null ? progress.completed+' of '+progress.total+' completed in this phase · ' : '')+elapsed+'s elapsed'),
      ['policy','live'].includes(progress?.phase) && h('p',{style:muted},'Waiting for the model response.')),
    confirm && h('div',{role:'alert',style:{margin:'12px 0'}},
      h('p',null,'The live run would use '+confirm.model+(confirm.cost == null ? ' with unknown cost.' : ' and cost about $'+Number(confirm.cost).toFixed(4)+'.')),
      h('button',{style:primary,disabled:busy,onClick:()=>run({model:confirm.model,provider:confirm.provider,accept_cost:true})},'Accept and run'),
      h('button',{style:link,disabled:busy,onClick:()=>{setLive(false);run({live:false})}},'Run without the live model')),
    report && h('pre',{style:{whiteSpace:'pre-wrap',fontFamily:'inherit',lineHeight:1.5,margin:'12px 0',fontSize:12}},report),
    message && h('p',{role:'alert',style:{whiteSpace:'pre-wrap'}},message),
    !confirm && h('button',{style:{...primary,marginTop:12},disabled:busy,onClick:()=>run()},busy?'Running…':report?'Run again':'Run the test'),
    h('button',{style:link,disabled:busy,onClick:onDone},'Back to overview'))
}

function Panel({ctx}) {
  const {data,error,session,profile,refresh} = useStatus(ctx)
  const [view,setView] = useState('home')
  const [busy,setBusy] = useState(false)
  const [message,setMessage] = useState('')
  useEffect(()=>{setView('home');setMessage('')},[profile])
  const home=()=>{setView('home');setMessage('');refresh()}
  async function check() {
    setBusy(true);setMessage('')
    try {const r=await ctx.rest('/check',{method:'POST',body:{profile},timeoutMs:155000});setMessage(r.message)} catch(e) {setMessage(String(e.message || e))} finally {setBusy(false);refresh()}
  }
  const state=data?.state || 'unknown'
  let body
  if(view==='profiles') body=h('div',null,h(Profiles,{ctx,profile,onChanged:refresh}),h('button',{style:link,onClick:home},'Back to overview'))
  else if(view==='settings') body=h(Settings,{ctx,profile,onDone:home})
  else if(view==='test') body=h(Test,{ctx,profile,onDone:home})
  else {
    const checks=data?.checks || {}
    const next=state==='inactive'?'This profile is not protected. Protect it to check every tool call against the task you asked for.':state==='restart_required'?data.guidance:state==='active'?'This chat’s permissions are checked before every tool call.':state==='ready'||state==='enabled'?'Your next message creates task permissions.':state==='expired'?'This chat’s policy expired. Start a new chat to create fresh task permissions.':data?.guidance || error || 'Checking…'
    body=h('section',{style:box},
      h('strong',{style:{color:colors[state]}},labels[state]),
      h('p',{style:{marginTop:10,lineHeight:1.6}},next),
      data?.checks && h('p',{style:{marginTop:10}},'Enforcement: '+(enforcement[data.overall]||'UNVERIFIED')),
      checks.compiler && h('p',{style:muted},'Compiler health: '+checks.compiler.status.replace('_',' ')+' — '+checks.compiler.message),
      data && h('p',{style:muted},'Compiler: '+data.compiler.model+' · '+data.compiler.routing+(data.compiler.note?' · '+data.compiler.note:'')),
      data && h('p',{style:muted},'Approvals: '+data.approval_mode+' · '+(data.human_approval?'you decide in Hermes’ approval dialog':'approval may be automatic')),
      data?.unprotected_profiles?.length>0 && h('p',{style:{...muted,marginTop:8}},'Not protected: '+data.unprotected_profiles.join(', ')),
      data?.audit_error && h('p',{role:'alert',style:{marginTop:10}},data.audit_error),
      state==='fallback' && h('p',{role:'alert',style:{marginTop:10}},(data?.policy?.compiler_error || data?.last_compilation?.details?.error || 'The policy compiler failed.')+' Your prohibitions remain active; consequential actions need your approval.'),
      message && h('p',{role:'status',style:{marginTop:10}},message),
      h('button',{style:{...primary,marginTop:14},disabled:busy||state==='compiling',onClick:state==='inactive'||state==='unknown'?()=>setView('profiles'):()=>setView('test')},
        busy?'Checking…':state==='inactive'||state==='unknown'?'Protect profiles':'Test this profile'),
      h('div',{style:{display:'flex',gap:14,flexWrap:'wrap',marginTop:6}},
        h('button',{style:link,onClick:()=>setView('profiles')},'Profiles'),
        h('button',{style:link,onClick:()=>setView('settings')},'Settings'),
        !['inactive','unknown'].includes(state) && h('button',{style:link,disabled:busy,onClick:check},'Check the compiler (one model call)')))
  }
  return h('div',{style:{padding:20,overflow:'auto',overflowWrap:'anywhere',height:'100%',color:'var(--ui-text-primary)',fontSize:13}},
    h('div',{style:{marginBottom:14}},h('h2',{style:{fontSize:21,fontWeight:650}},'AgentsFence'),h('p',{style:muted},'Profile: '+profile+' · '+(data?.version || ''))),
    body,
    view==='home' && h('details',{style:box},h('summary',{style:{fontWeight:600,cursor:'pointer'}},'Permissions and audit'),
      h('details',{style:{marginTop:12}},h('summary',{style:{cursor:'pointer'}},'Current chat permissions'),h('pre',{style:{whiteSpace:'pre-wrap',fontFamily:'inherit',lineHeight:1.6,marginTop:10}},data?.policy_text || 'No current task policy. Send a message to create one.')),
      h('details',{style:{marginTop:12}},h('summary',{style:{cursor:'pointer'}},session?'Recent decisions in this chat':'Recent activity in this profile'),
        ...(data?.audit || []).slice(-12).reverse().map((r,i)=>h('div',{key:i,style:{padding:'8px 0',borderBottom:'1px solid var(--ui-stroke-secondary)'}},h('strong',null,[r.decision,r.tool,r.event].filter(Boolean).join(' · ')),h('div',{style:{fontSize:11,color:'var(--ui-text-secondary)'}},new Date(r.timestamp).toLocaleString()+' · '+(r.session_id || 'profile')),r.reason && h('p',null,r.reason)))),
      h('p',{style:{...muted,marginTop:12}},'The full log: `agentsfence audit` in a terminal. In Hermes plugin settings, the AgentsFence Desktop switch shows this pane.'),
      h('button',{style:link,onClick:()=>host.navigate('/capabilities?tab=plugins')},'Open Hermes plugin settings')))
}

export default {
  id:'agentsfence',name:'AgentsFence',defaultEnabled:false,
  register(ctx) {
    const open=()=>{
      if(host.openWorkspace)host.openWorkspace('agentsfence:status',{title:'AgentsFence',render:()=>h(Panel,{ctx})})
      else host.notify({kind:'info',message:'Open the AgentsFence pane from the panel picker.'})
    }
    ctx.register({id:'panel',area:'panes',title:'AgentsFence',data:{placement:'right',width:'420px'},render:()=>h(Panel,{ctx})})
    ctx.register({id:'status',area:'statusBar.right',order:130,render:()=>h(Chip,{ctx,open})})
  }
}
