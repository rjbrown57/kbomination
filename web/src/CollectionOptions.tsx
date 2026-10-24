import React from 'react';
import type { CollectionOptions } from './api';

const lists = [
  ['exclude_namespaces', 'Exclude namespaces', 'None'],
  ['include_kinds', 'Include kinds', 'All kinds'],
  ['exclude_kinds', 'Exclude kinds', 'None'],
  ['image_src', 'Image sources · in priority order', 'docker,containerd,podman,remote'],
  ['db_repository', 'Vulnerability database mirrors · in priority order', 'Trivy defaults'],
  ['java_db_repository', 'Java database mirrors · in priority order', 'Trivy defaults'],
] as const;
const numbers = [
  ['qps', 'API queries per second', 5, 0.001, 'any'],
  ['burst', 'API request burst', 10, 1, '1'],
  ['parallel', 'Scan parallelism · 0 = automatic', 5, 0, '1'],
] as const;
const toggles = [
  ['scan_images', 'Download and scan images'],
  ['offline_scan', 'Disable dependency-identification API requests'],
  ['skip_db_update', 'Skip vulnerability database updates'],
  ['skip_java_db_update', 'Skip Java database updates'],
] as const;

export function CollectionOptionsEditor({value, onChange}: {value: CollectionOptions; onChange: (value: CollectionOptions) => void}) {
  return <details className="metadata-editor collection-options"><summary>Advanced collection options</summary><div className="metadata-fields">
    <p className="hint">Lists are comma-separated. Image scanning increases collection time and artifact size. Parallelism applies within each Trivy scan; up to two clusters are collected concurrently.</p>
    <div className="form-grid">
      {lists.map(([key,label,placeholder])=><label key={key}>{label}<input placeholder={placeholder} value={value[key]?.join(',')??''} onChange={e=>onChange({...value,[key]:e.target.value.trim()?e.target.value.split(','):[]})}/></label>)}
      {numbers.map(([key,label,placeholder,min,step])=><label key={key}>{label}<input type="number" min={min} step={step} placeholder={String(placeholder)} value={value[key]??''} onChange={e=>onChange({...value,[key]:e.target.value===''?undefined:Number(e.target.value)})}/></label>)}
      <label>Cache directory<input placeholder="Trivy default" value={value.cache_dir??''} onChange={e=>onChange({...value,cache_dir:e.target.value})}/></label>
      <label>CA certificate · PEM path<input value={value.cacert??''} onChange={e=>onChange({...value,cacert:e.target.value})}/></label>
    </div>
    {toggles.map(([key,label])=><label className="check" key={key}><input type="checkbox" checked={value[key]??false} onChange={e=>onChange({...value,[key]:e.target.checked})}/>{label}</label>)}
    <p className="hint">Paths refer to the machine or container running the collector. Skipping updates requires preprovisioned databases. Offline dependency identification still requires Kubernetes access and may require registry access and database downloads.</p>
  </div></details>;
}
