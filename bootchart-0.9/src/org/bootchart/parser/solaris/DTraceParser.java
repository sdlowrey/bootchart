/*
 * Bootchart -- Boot Process Visualization
 *
 * Copyright (C) 2004  Ziga Mahkovec <ziga.mahkovec@klika.si>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package org.bootchart.parser.solaris;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bootchart.common.BootStats;
import org.bootchart.common.CPUSample;
import org.bootchart.common.Common;
import org.bootchart.common.DiskTPutSample;
import org.bootchart.common.FileOpenSample;
import org.bootchart.common.Process;
import org.bootchart.common.ProcessSample;
import org.bootchart.common.ProcessTree;
import org.bootchart.common.PsStats;
import org.bootchart.common.Stats;

/**
 * DTraceParser parses log files produced with the bootchart DTrace script
 * for Solaris 10.  The D script produces a single log file containing
 * process execution, CPU scheduler and disk I/O information.
 */
public class DTraceParser {
	private static final Logger log = Logger.getLogger(DTraceParser.class.getName());

	/** The probe name for process startup. */
	private static final List PROBES_PROC_START =
		Arrays.asList(new String[]{"create", "exec-success"});
	
	/** The probe name for process completion. */
	private static final String PROBE_PROC_END    = "exit";
	
	/** The probe name for profiling. */
	private static final String PROBE_PROF        = "profile";
	
	/** The probe name for process CPU statistics. */
	private static final String PROBE_PROF_CPU    = "cputime";

	/** The probe name for disk IO duration. */
	private static final String PROBE_PROF_DISKIO_TIME = "diskio_duration";
	
	/** The probe name for disk IO throughput. */
	private static final String PROBE_PROF_DISKIO_BYTES = "diskio_bytes";
	
	/** The probe name for file open count. */
	private static final String PROBE_PROF_FILEOPEN = "file_open_count";
	
	/** The probe name for max thread count. */
	private static final String PROBE_PROF_THREADS = "max_active_thread_count";

	/** The probe name for virtual memory pageins/outs. */
	private static final String PROBE_PROF_VM     = "paging";
	
	/** The probe name for boot end. */
	private static final String PROBE_END         = "boot_end";
	
	
	private static final String CPU_ON      = "oncpu";
	private static final String CPU_SYS     = "sys";
	private static final String CPU_IOWAIT  = "iowait";
	private static final String CPU_IDLE    = "idle";
	
	//private static final String IO_TIME_READ      = "read_duration";
	//private static final String IO_TIME_WRITE     = "write_duration";
	private static final String IO_BYTES_READ     = "read_bytes";
	private static final String IO_BYTES_WRITTEN  = "write_bytes";
	
	/**
	 * Profile sample encapsulates the output of DTrace aggregations.
	 */
	private static class ProfileSample implements Comparable {
		/** Sample time. */
		public long time;
		/** Sample type. */
		public String type;
		/** Process PID. */
		public int pid;
		/** Sample value. */
		public long value;
		
		public int compareTo(Object o) {
			if (!(o instanceof ProfileSample)) {
				throw new ClassCastException();
			}
			// sort by time and value
			int timeDiff = (int)(time - ((ProfileSample)o).time);
			if (timeDiff == 0) {
				return (int)(((ProfileSample)o).value - value);
			} else {
				return timeDiff;
			}
		}
		public String toString() {
			return time + " " + type + " " + pid + " " + value;
		}
	}
	
	/** The maximum number of lines to read. */
	private static final int MAX_SAMPLES = 100000;
	
	/**
	 * Parses the <code>dtrace</code> log file.
	 * 
	 * @param is            the input stream to parse
	 * @param prune         whether to prune the tree
	 * @param monitoredApp  monitored application (or <code>null</code> if
	 *                      the boot process is profiled)
	 * @return              boot statistics
	 * @throws IOException  if an I/O error occurs
	 */
	public static BootStats parseLog(InputStream is, String monitoredApp, boolean prune)
		throws IOException {
		
		BufferedReader reader = Common.getReader(is);
		String line = null;
		int num = 0;
		
		Map processMap = new TreeMap();
		List cpuTimeSamples = new ArrayList();
		List ioTimeSamples = new ArrayList();
		List ioBytesSamples = new ArrayList();
		List fopenSamples = new ArrayList();
		List threadSamples = new ArrayList();
		List vmSamples = new ArrayList();
		int samplePeriod = -1;
		long time = 0;
		long endTime = -1;
		
		
		// add the root (sched) process
		Process rootProc = new Process(0, "sched");
		rootProc.startTime = new Date(0);
		rootProc.active = true;
		processMap.put(new Integer(0), rootProc);
		
		while ((line = reader.readLine()) != null) {
			num++;
			if (num > MAX_SAMPLES) {
				log.warning("Maximum number of log lines exceeded.");
				break;
			}
			try {
				line = line.trim();
				if (line.length() == 0 || line.startsWith("#")) {
					continue;
				}
				if (line.startsWith("Time:")) {
					continue;
				}
				
				String[] tokens = line.split(" ");
				try {
					time = Long.parseLong(tokens[0]);
				} catch (NumberFormatException e) {
					log.log(Level.WARNING, "", e);
					continue;
				}
				String probe = tokens[1];
				
				if (PROBES_PROC_START.contains(probe)) {
					int pid = -1;
					int ppid = -1;
					String cmd = null;
					String args = null;
					for (int i=2; i<tokens.length; i++) {
						if (tokens[i].startsWith("pid=")) {
							pid = Integer.parseInt(tokens[i].substring("pid=".length()));
						} else if (tokens[i].startsWith("ps=")) {
							cmd = tokens[i].substring("ps=".length());
						} else if (tokens[i].startsWith("ppid=")) {
							ppid = Integer.parseInt(tokens[i].substring("ppid=".length()));
						} else if (tokens[i].startsWith("args=\"")) {
							StringBuffer sb = new StringBuffer();
							sb.append(tokens[i].substring("args=\"".length()));
							for (++i; i<tokens.length; i++) {
								sb.append(" " + tokens[i]);
							}
							while (sb.charAt(sb.length() - 1) != '\"') {
								line = reader.readLine();
								num++;
								sb.append(" " + line.trim());
							}
							sb.deleteCharAt(sb.length() - 1);
							args = sb.toString();
						}
					}
					if (args != null) {
						String fcmd = Common.formatCommand(args);
						if (fcmd != null) {
							cmd = fcmd;
						}
					}
					Process proc = new Process(pid, cmd);
					proc.ppid = ppid;
					proc.startTime = new Date(time);
					proc.active = false;
					
					Process forkProc = (Process)processMap.get(new Integer(pid));
					if (forkProc != null) {
						proc.startTime = forkProc.startTime;
					}
					processMap.put(new Integer(pid), proc);
					//fine(proc.toString());
					
				} else if (PROBE_PROC_END.equals(probe)) {
					int pid = -1;
					for (int i=2; i<tokens.length; i++) {
						if (tokens[i].startsWith("pid=")) {
							pid = Integer.parseInt(tokens[i].substring("pid=".length()));
						}
					}
					Process proc = (Process)processMap.get(new Integer(pid));
					if (proc != null) {
						proc.duration = time - proc.startTime.getTime();
					} else {
						log.warning("Unknown process exiting: " + pid);
					}
				} else if (PROBE_PROF.equals(probe)) {
					String profile = tokens[2];
					samplePeriod = Integer.parseInt(tokens[3]);
					
					reader.mark(8096);
					line = reader.readLine();
					num++;
					while (line.startsWith("\t")) {
						line = line.trim();
						String[] cpuTokens = line.split(" ");
						ProfileSample sample = new ProfileSample();
						sample.time = Integer.parseInt(cpuTokens[0]) * samplePeriod;
						if (endTime == -1 || sample.time < endTime) {
							sample.type = cpuTokens[1];
							sample.pid = Integer.parseInt(cpuTokens[3]);
							sample.value = Long.parseLong(cpuTokens[4]);
							if (PROBE_PROF_CPU.equals(profile)) {
								cpuTimeSamples.add(sample);
							} else if (PROBE_PROF_DISKIO_TIME.equals(profile)) {
								ioTimeSamples.add(sample);
							} else if (PROBE_PROF_DISKIO_BYTES.equals(profile)) {
								ioBytesSamples.add(sample);
							} else if (PROBE_PROF_FILEOPEN.equals(profile)) {
								fopenSamples.add(sample);
							} else if (PROBE_PROF_THREADS.equals(profile)) {
								threadSamples.add(sample);
							} else if (PROBE_PROF_VM.equals(profile)) {
								vmSamples.add(sample);
							}
						}
						reader.mark(8096);
						line = reader.readLine();
						num++;
					}
					reader.reset();
					
				} else if (PROBE_END.equals(probe)) {
					endTime = time;
				}
				
			} catch (RuntimeException e) {
				log.log(Level.SEVERE, "", e);
			}
				
		}
		log.fine("Parsed " + num + " dtrace log lines");
		
		if (endTime == -1) {
			// boot end wasn't logged, use last sample time
			endTime = time;
		}
		
		// set process parents and duration
		for (Iterator i=processMap.values().iterator(); i.hasNext(); ) {
			Process p = (Process)i.next();
			if (p.ppid != -1) {
				p.parent = (Process)processMap.get(new Integer(p.ppid));
			}
			if (p.duration == -1) {
				p.duration = endTime - p.startTime.getTime();
			}
		}
		
		// extract CPU and process samples from the cpuTime samples
		Stats cpuStats = new Stats();
		Collections.sort(cpuTimeSamples);
		for (int i=0; i<cpuTimeSamples.size(); i++) {
			ProfileSample sample = (ProfileSample)cpuTimeSamples.get(i);
			long stime = sample.time;
			
			List tickSamples = new ArrayList();
			while (sample.time == stime) {
				tickSamples.add(sample);
				i++;
				if (i == cpuTimeSamples.size()) {
					break;
				}
				sample = (ProfileSample)cpuTimeSamples.get(i);
			}
			i--;
			
			long onCpuTime = 0;
			long sysTime = 0;
			long ioTime = 0;
			long idleTime = 0;
			for (Iterator j=tickSamples.iterator(); j.hasNext(); ) {
				ProfileSample s = (ProfileSample)j.next();
				if (CPU_ON.equals(s.type)) {
					onCpuTime += s.value;
				} else if (CPU_SYS.equals(s.type)) {
					sysTime += s.value;
				} else if (CPU_IOWAIT.equals(s.type)) {
					ioTime += s.value;
				} else if (CPU_IDLE.equals(s.type)) {
					idleTime += s.value;
				}
			}
			Set tickProcesses = new HashSet();
			for (Iterator j=tickSamples.iterator(); j.hasNext(); ) {
				ProfileSample s = (ProfileSample)j.next();
				int state = Process.STATE_SLEEPING;
				if (CPU_ON.equals(s.type) || CPU_SYS.equals(s.type)) {
					state = Process.STATE_RUNNING;
				} else if (CPU_IOWAIT.equals(s.type)) {
					state = Process.STATE_WAITING;
				}
				Process proc = (Process)processMap.get(new Integer(s.pid));
				if (proc != null && proc.pid != 0 && !tickProcesses.contains(proc)) {
					double user = 0.0;
					double sys = 0.0;
					if (CPU_ON.equals(s.type)) {
						user = (double)s.value / onCpuTime;
						proc.active = true;
					}
					sys = 0.0; // TODO: Get process system time
					CPUSample cpuSample = new CPUSample(null, user, sys, 0.0);
					ProcessSample procSample = new ProcessSample(
						new Date(s.time), state, cpuSample, null, null);
					proc.samples.add(procSample);
					tickProcesses.add(proc);
				}
			}
			double user = onCpuTime > 0 ?
				(double)(onCpuTime - sysTime - idleTime) / Math.max(onCpuTime, samplePeriod) : 0.0;
			double sys = onCpuTime > 0 ?
				(double)sysTime / Math.max(onCpuTime, samplePeriod) : 0.0;
			double io = Math.max(0.0, (double)(samplePeriod - onCpuTime) / samplePeriod);
			CPUSample cpuSample =
				new CPUSample(new Date(stime), user, sys, io);
			cpuStats.addSample(cpuSample);
		}
		cpuTimeSamples = null;
		
		// extract disk IO throughput
		Stats diskStats = new Stats();
		Collections.sort(ioBytesSamples);
		for (int i=0; i<ioBytesSamples.size(); i++) {
			ProfileSample sample = (ProfileSample)ioBytesSamples.get(i);
			long stime = sample.time;
			List tickSamples = new ArrayList();
			long bytesRead = 0;
			long bytesWritten = 0;
			while (sample.time == stime) {
				tickSamples.add(sample);
				if (IO_BYTES_READ.equals(sample.type)) {
					bytesRead += sample.value;
				} else if (IO_BYTES_WRITTEN.equals(sample.type)) {
					bytesWritten += sample.value;
					}
				i++;
				if (i == ioBytesSamples.size()) {
					break;
				}
				sample = (ProfileSample)ioBytesSamples.get(i);
			}
			i--;
			double read = (double)bytesRead * 1000.0 / 1024.0 / samplePeriod;
			double write = (double)bytesWritten * 1000.0 / 1024.0 / samplePeriod;
			DiskTPutSample diskTPutSample = 
				new DiskTPutSample(new Date(stime), read, write);
			diskStats.addSample(diskTPutSample);
		}
		ioBytesSamples = null;
		
		// extract file opens
		Collections.sort(fopenSamples);
		for (int i=0; i<fopenSamples.size(); i++) {
			ProfileSample sample = (ProfileSample)fopenSamples.get(i);
			long stime = sample.time;
			List tickSamples = new ArrayList();
			int files = 0;
			while (sample.time == stime) {
				tickSamples.add(sample);
				files += sample.value;
				i++;
				if (i == fopenSamples.size()) {
					break;
				}
				sample = (ProfileSample)fopenSamples.get(i);
			}
			i--;
			FileOpenSample fopenSample =
				new FileOpenSample(new Date(stime), files * 1000 / samplePeriod);
			diskStats.addSample(fopenSample);
		}
		fopenSamples = null;

		
		List processList = new ArrayList(processMap.values());
        PsStats psStats = new PsStats();
        psStats.processList = processList;
        psStats.samplePeriod = samplePeriod;
		ProcessTree procTree = new ProcessTree(psStats, monitoredApp, prune);
		
		return new BootStats(cpuStats, diskStats, procTree);
	}
	
}
