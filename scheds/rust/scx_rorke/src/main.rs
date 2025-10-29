mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod config;
use config::*;

mod stats;
use stats::Metrics;

use std::env;
use std::fs;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::os::fd::{AsFd, AsRawFd};

use libc::{sched_param, sched_setscheduler};
use std::process::Command;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;

use log::debug;
use log::info;

use perf_event_open_sys as sys;

use scx_stats::prelude::*;

use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::import_enums;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

const SCHED_EXT: i32 = 7;
const SCHEDULER_NAME: &'static str = "scx_rorke";

lazy_static::lazy_static! {
    static ref NR_POSSIBLE_CPUS: usize = libbpf_rs::num_possible_cpus().unwrap();
}

#[derive(Debug, Parser)]
struct Opts {
    /// Number of CPUs
    #[clap(short = 'n', long, default_value = "2")]
    num_cpus: u32,

    /// Timer interval in microseconds
    #[clap(short = 't', long, default_value = "100")]
    timer_interval: u64,

    /// Config file
    #[clap(short = 'f', long)]
    config_file: Option<String>,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue, default_value = "false")]
    partial: bool,

    /// Enable verbose output including libbpf details.
    /// Specify multiple times to increase verbosity.
    #[clap(short='v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Print version and exit.
    #[clap(long)]
    version: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,
}
fn convert_cpu_ctxs(cpu_ctxs: Vec<bpf_intf::cpu_ctx>) -> Vec<Vec<u8>> {
    cpu_ctxs
        .into_iter()
        .map(|cpu_ctx| {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &cpu_ctx as *const bpf_intf::cpu_ctx as *const u8,
                    std::mem::size_of::<bpf_intf::cpu_ctx>(),
                )
            };
            bytes.to_vec()
        })
        .collect()
}

fn get_per_cpu_preempted(skel: &BpfSkel) -> Result<Vec<u64>> {
    let key = (0_u32).to_ne_bytes();
    let mut cpu_ctxs: Vec<bpf_intf::cpu_ctx> = vec![];
    let cpu_ctxs_vec = skel
        .maps
        .cpu_ctx_stor
        .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();

    for cpu in 0..*NR_POSSIBLE_CPUS {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });
    }

    let mut cpus_preempted = vec![];
    for cpu_ctx in cpu_ctxs.iter() {
        cpus_preempted.push(cpu_ctx.preempted);
    }
    return Ok(cpus_preempted);
}

fn initialize_cpu_ctxs(skel: &BpfSkel, cpu_allocation: &Vec<u64>) -> Result<()> {
    let key = (0_u32).to_ne_bytes();
    let mut cpu_ctxs: Vec<bpf_intf::cpu_ctx> = vec![];
    let cpu_ctxs_vec = skel
        .maps
        .cpu_ctx_stor
        .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();

    for cpu in 0..*NR_POSSIBLE_CPUS {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });
    }

    for (cpu, vm_id) in cpu_allocation.iter().enumerate() {
        cpu_ctxs[cpu].vm_id = *vm_id;
        info!("cpu - {} assigned to vm - {}", cpu, *vm_id);
    }

    skel.maps
        .cpu_ctx_stor
        .update_percpu(&key, &convert_cpu_ctxs(cpu_ctxs), libbpf_rs::MapFlags::ANY)
        .context("Failed to update cpu_ctx")?;

    Ok(())
}

struct SchedMetric {
    name: String, // human-readable label
    config: u64, // what to count, e.g. PERF_COUNT_HW_INSTRUCTIONS
    sample_period: u64, // perf event is triggered every sample_period counts
    prog_fd: i32, // fd of the BPF program to attach
	link_fds: Vec<i32>, // fds of the perf event link, closed on drop
}

fn prog_fd<P: AsFd>(prog: &P) -> i32 {
    prog.as_fd().as_raw_fd()
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    sched_metrics: Vec<SchedMetric>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        set_rlimit_infinity();

        // Open the eBPF object for verification
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        init_libbpf_logging(None);
        info!(
            "Running scx_rorke (build_id: {})",
            *build_id::SCX_FULL_VERSION
        );
        info!("Opts: {:?}", opts);
        let mut skel = scx_ops_open!(skel_builder, open_object, rorke).unwrap();

        // Parse json config file
        let config_path = match &opts.config_file {
            Some(path) => PathBuf::from(path),
            None => {
                let home_dir = env::var("HOME").expect("Failed to get $HOME env variable");
                PathBuf::from(home_dir).join("config.json")
            }
        };
        let vm_config =
            parse_vm_config(&fs::read_to_string(config_path).context("Failed to find file")?)
                .context("Failed to parse config file")?;
        let cpu_allocation = allocate_cpus_to_vms(&vm_config, opts.num_cpus);
        info!("CPU allocation: {:?}", cpu_allocation);

        // Initialize skel
        skel.maps.rodata_data.nr_cpus = opts.num_cpus;
        skel.maps.rodata_data.nr_vms = vm_config.len() as u32;
        skel.maps.rodata_data.timer_interval_ns = opts.timer_interval * 1000;
        for (i, vm) in vm_config.iter().enumerate() {
            skel.maps.rodata_data.vms[i] = vm.vm_id;
        }
        if opts.partial {
            skel.struct_ops.rorke_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }
        skel.maps.rodata_data.debug = opts.verbose as u32;

        let mut skel = scx_ops_load!(skel, rorke, uei)?;

		// This needs to be initalized after skel is loaded to get valid prog fds
		let mut sched_metrics: Vec<SchedMetric> = vec![
			SchedMetric {
				name: "instructions".to_string(),
				config: sys::bindings::PERF_COUNT_HW_INSTRUCTIONS as u64,
				sample_period: 1_000,
				prog_fd: prog_fd(&skel.progs.count_instr),
				link_fds: vec![],
			},
			SchedMetric {
				name: "cycles".to_string(),
				config: sys::bindings::PERF_COUNT_HW_CPU_CYCLES as u64,
				sample_period: 1_000,
				prog_fd: prog_fd(&skel.progs.count_cycles),
				link_fds: vec![],
			},
		];

        for cpu in 0..opts.num_cpus {
			for metric in sched_metrics.iter_mut() {
				let mut attrs = sys::bindings::perf_event_attr::default();
				attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
				attrs.type_ = sys::bindings::PERF_TYPE_HARDWARE;
				attrs.set_disabled(1);
				attrs.set_exclude_kernel(1);
				attrs.set_exclude_hv(1);
				attrs.config = metric.config;
				attrs.__bindgen_anon_1.sample_period = metric.sample_period;
				let perf_fd = unsafe {
					sys::perf_event_open(&mut attrs, -1, cpu as i32, -1, 0)
				};
				if perf_fd < 0 {
					return Err(anyhow!("Cannot open perf event for pcpu {:?} metric {:?}", cpu, metric.name));
				}
				// Create link between perf event and BPF program
				let link_fd = unsafe {
					libbpf_sys::bpf_link_create(
						metric.prog_fd,
						perf_fd,
						libbpf_sys::BPF_PERF_EVENT as u32,
						std::ptr::null(),
					)
				};
				if link_fd < 0 {
					return Err(anyhow!("Failed to create perf event link for CPU {} metric {:?}", cpu, metric.name));
				}
				// Enable the perf event
				let enable_rc = unsafe {
					libc::ioctl(perf_fd, 0x2400, 0)
				};
				if enable_rc != 0 {
					return Err(anyhow!("Failed to enable perf event for CPU {} metric {:?}", cpu, metric.name));
				}

				metric.link_fds.push(link_fd);
			}
        }

        initialize_cpu_ctxs(&skel, &cpu_allocation)?;

        let struct_ops = Some(scx_ops_attach!(skel, rorke)?);
        info!("scx_rorke started");

        // Set VMs to sched_ext class
        for vm in vm_config.iter() {
            let vcpus = &vm.vcpus;
            debug!("vm_id: {:?} vcpus: {:?}", vm.vm_id, vcpus);

            // pCPUs assigned to this VM
            let pcpus_str = cpu_allocation
                .iter()
                .enumerate()
                .filter_map(|(pcpu, owner)| {
                    if *owner == vm.vm_id as u64 {
                        Some(pcpu.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(",");

            if pcpus_str.is_empty() {
                return Err(anyhow!("No pCPUs allocated for vm_id {:?}", vm.vm_id));
            }

            for (vcpu_idx, vcpu_pid) in vcpus.iter().enumerate() {
                let param = sched_param { sched_priority: 0 };
                let result = unsafe {
                    sched_setscheduler(*vcpu_pid as i32, SCHED_EXT, &param as *const sched_param)
                };

                if result == -1 {
                    return Err(anyhow!("Failed to set SCHED_EXT for vcpu: {:?}", vcpu_pid));
                }
                debug!("Set SCHED_EXT for vcpu: {:?}", vcpu_pid);

                let status = Command::new("virsh")
                    .arg("vcpupin")
                    .arg(vm.vm_name.clone())
                    .arg(vcpu_idx.to_string())
                    .arg(&pcpus_str)
                    .stdout(std::process::Stdio::null()) // Suppress terminal output
                    .status()
                    .context("failed to execute virsh vcpupin")?;

                if !status.success() {
                    return Err(anyhow!(
                        "failed to pin vcpu for vm_id {:?} vcpu {} (pcpus={})",
                        vm.vm_id,
                        vcpu_idx,
                        pcpus_str
                    ));
                }
            }
        }

        // Start Stats server
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        Ok(Self {
            skel,
            struct_ops,
            stats_server,
			sched_metrics,
        })
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
            nr_running: self.skel.maps.bss_data.nr_running,
            nr_cpus: self.skel.maps.rodata_data.nr_cpus as u64,
            nr_kthread_dispatches: self.skel.maps.bss_data.nr_kthread_dispatches,
            nr_direct_to_idle_dispatches: self.skel.maps.bss_data.nr_direct_to_idle_dispatches,
            nr_vm_dispatches: self.skel.maps.bss_data.nr_vm_dispatches,
            per_cpu_preempted: get_per_cpu_preempted(&self.skel)
                .expect("Failed to get per_cpu_preempted"),
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
        
        // Clean up perf links
		for metric in self.sched_metrics.iter() {
			for link_fd in metric.link_fds.iter() {
				unsafe {
					libc::close(*link_fd);
				}
			}
		}
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!("scx_rorke: {}", *build_id::SCX_FULL_VERSION);
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Failed to set Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            stats::monitor(Duration::from_secs_f64(intv), shutdown_copy).unwrap()
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
