use anyhow::{anyhow, Result};
use log::debug;
use netidx::{
    config::Config,
    path::Path,
    publisher::{BindCfg, Publisher, PublisherBuilder, UpdateBatch, Val, Value},
    resolver_client::DesiredAuth,
};
use netidx_tools_core::ClientParams;
use std::collections::{HashMap, HashSet};
use structopt::StructOpt;
use sysinfo::{DiskExt, NetworkExt, PidExt, ProcessExt, System, SystemExt};
use tokio::{
    task,
    time::{sleep, Duration, Instant},
};

#[derive(StructOpt)]
struct SysinfoOpt {
    #[structopt(flatten)]
    common: ClientParams,
    #[structopt(short = "i", long = "interval", default_value = "1")]
    interval: u64,
    #[structopt(short = "d", long = "deep-interval", default_value = "60")]
    deep_interval: u64,
    #[structopt(
        short = "b",
        long = "bind",
        help = "configure the bind address e.g. 192.168.0.0/16, 127.0.0.1:5000"
    )]
    bind: Option<BindCfg>,
    #[structopt(
        long = "netidx-base",
        help = "the base path to publish under",
        default_value = "/local/system/sysfs"
    )]
    netidx_base: Path,
    #[structopt(short = "h", long = "host", help = "override box hostname")]
    host: Option<String>,
}

fn update_network_interface_stats(
    publisher: &Publisher,
    batch: &mut UpdateBatch,
    base: &Path,
    sys: &System,
    interfaces_map: &mut HashMap<String, (Val, Val)>,
) -> Result<()> {
    let mut latest_interfaces = HashSet::new();
    for (interface_name, data) in sys.networks() {
        latest_interfaces.insert(interface_name.clone());
        let rx_v = Value::U64(data.received());
        let tx_v = Value::U64(data.transmitted());
        match interfaces_map.get(interface_name) {
            Some((rx, tx)) => {
                rx.update(batch, rx_v);
                tx.update(batch, tx_v);
            }
            None => {
                let interface_base = base.append(interface_name);
                debug!("new interface: {}", interface_base);

                let rx = publisher.publish(interface_base.append("rx"), rx_v)?;
                let tx = publisher.publish(interface_base.append("tx"), tx_v)?;
                interfaces_map.insert(interface_name.clone(), (rx, tx));
            }
        }
    }
    // delete interfaces that no longer exist
    let previous_interfaces = interfaces_map.keys().cloned().collect::<HashSet<String>>();
    let lost_interfaces = previous_interfaces.difference(&latest_interfaces);
    for key in lost_interfaces {
        debug!("interface gone: {}", key);
        interfaces_map.remove(key);
    }
    Ok(())
}

fn update_disk_stats(
    publisher: &Publisher,
    batch: &mut UpdateBatch,
    base: &Path,
    sys: &System,
    disks_map: &mut HashMap<String, (Val, Val, Val, Val)>,
) -> Result<()> {
    let mut latest_disks: HashSet<String> = HashSet::new();
    for disk in sys.disks() {
        let mount_point = disk.mount_point().to_str().unwrap_or("").to_string();
        latest_disks.insert(mount_point.clone());

        let block_device = disk.name().to_str().unwrap_or("").to_string();
        let avail_space = disk.available_space();
        let total_space = disk.total_space();
        match disks_map.get(&mount_point) {
            Some((_mp_v, bd, total, avail)) => {
                // the block device could theoretically change for the mount point
                bd.update(batch, block_device);
                total.update(batch, total_space);
                avail.update(batch, avail_space);
            }
            None => {
                let disk_base =
                    base.append("disks").append(&Path::escape(&mount_point.clone()));
                debug!("new disk: {}", disk_base);
                let mp = publisher
                    .publish(disk_base.append("mount_point"), mount_point.clone())?;
                let bd =
                    publisher.publish(disk_base.append("block_device"), block_device)?;
                let total =
                    publisher.publish(disk_base.append("total_space"), total_space)?;
                let avail =
                    publisher.publish(disk_base.append("avail_space"), avail_space)?;
                disks_map.insert(mount_point, (mp, bd, total, avail));
            }
        }
    }
    let previous_disks = disks_map.keys().cloned().collect::<HashSet<String>>();
    let lost_disks = previous_disks.difference(&latest_disks);
    for key in lost_disks {
        debug!("disk gone: {}", key);
        disks_map.remove(key);
    }
    Ok(())
}

struct ProcStat {
    name: Val,
    uid: Val,
    gid: Val,
    cmdline: Val,
    exe: Val,
    cpu: Val,
    vsize: Val,
    rss: Val,
    disk_read: Val,
    disk_written: Val,
}

fn update_procs_stats(
    publisher: &Publisher,
    batch: &mut UpdateBatch,
    base: &Path,
    sys: &System,
    procs_map: &mut HashMap<u32, ProcStat>,
) -> Result<()> {
    let mut latest_pids: HashSet<u32> = HashSet::new();
    for (pid, proc) in sys.processes() {
        let pid = pid.as_u32();
        latest_pids.insert(pid);

        let new_name = proc.name();
        let new_exe = proc.exe().to_path_buf().to_str().unwrap_or("").to_string();
        let new_cpu = proc.cpu_usage();
        let new_cmdline = proc.cmd().join(" ");
        // TODO: uid/gid might break on Windows because Sid can't fit in u32. change to string
        let new_uid: u32 = proc.user_id().map(|uid| **uid).unwrap_or(0);
        let new_gid: u32 = proc.group_id().map(|gid| *gid).unwrap_or(0);

        let new_vsize = proc.virtual_memory();
        let new_rss = proc.memory();
        let du = proc.disk_usage();
        let new_disk_read = du.read_bytes;
        let new_disk_written = du.written_bytes;

        match procs_map.get_mut(&pid) {
            Some(proc_stat) => {
                // TODO: is there a way to just see the previous published value so we don't clone needlessly to update it?
                proc_stat.name.update_changed(batch, new_name.to_string().clone());
                proc_stat.cmdline.update_changed(batch, new_cmdline.clone());
                proc_stat.exe.update_changed(batch, new_exe.clone());
                proc_stat.uid.update_changed(batch, new_uid);
                proc_stat.gid.update_changed(batch, new_gid);
                proc_stat.cpu.update(batch, new_cpu);
                proc_stat.vsize.update(batch, new_vsize);
                proc_stat.rss.update(batch, new_rss);
                proc_stat.disk_read.update(batch, new_disk_read);
                proc_stat.disk_written.update(batch, new_disk_written);
            }
            None => {
                let proc_base = base.append("procs").append(&pid.to_string());
                debug!("new proc: {}", proc_base);

                let name = publisher
                    .publish(proc_base.append("name"), new_name.to_string().clone())?;
                let cmdline = publisher
                    .publish(proc_base.append("cmdline"), new_cmdline.clone())?;
                let exe = publisher.publish(proc_base.append("exe"), new_exe.clone())?;
                let uid = publisher.publish(proc_base.append("uid"), new_uid)?;
                let gid = publisher.publish(proc_base.append("gid"), new_gid)?;
                let cpu = publisher.publish(proc_base.append("cpu"), new_cpu)?;
                let vsize = publisher.publish(proc_base.append("vsize"), new_vsize)?;
                let rss = publisher.publish(proc_base.append("rss"), new_rss)?;
                let disk_read =
                    publisher.publish(proc_base.append("disk_read"), new_disk_read)?;
                let disk_written = publisher
                    .publish(proc_base.append("disk_written"), new_disk_written)?;

                procs_map.insert(
                    pid,
                    ProcStat {
                        name,
                        cmdline,
                        exe,
                        uid,
                        gid,
                        cpu,
                        vsize,
                        rss,
                        disk_read,
                        disk_written,
                    },
                );
            }
        }
    }
    let previous_pids = procs_map.keys().cloned().collect::<HashSet<u32>>();
    let lost_pids = previous_pids.difference(&latest_pids);
    for key in lost_pids {
        debug!("proc gone: {}", key);
        procs_map.remove(key);
    }
    Ok(())
}

async fn run(opt: SysinfoOpt, cfg: Config, auth: DesiredAuth) -> Result<()> {
    let mut sys = System::new_all();
    let host = match opt.host {
        Some(h) => h,
        None => sys
            .host_name()
            .ok_or(anyhow!("could not determine hostname, provide -host arg"))?,
    };
    let base = opt.netidx_base.append(&host);
    let publisher =
        PublisherBuilder::new(cfg).desired_auth(auth).bind_cfg(opt.bind).build().await?;

    task::block_in_place(|| sys.refresh_all());
    let init_loadavg = sys.load_average();

    let total_memory = publisher
        .publish(Path::from(format!("{}/total_memory", base)), sys.total_memory())?;
    let used_memory = publisher
        .publish(Path::from(format!("{}/used_memory", base)), sys.used_memory())?;
    let total_swap = publisher
        .publish(Path::from(format!("{}/total_swap", base)), sys.total_swap())?;
    let used_swap =
        publisher.publish(Path::from(format!("{}/used_swap", base)), sys.used_swap())?;

    let loadavg1 = publisher
        .publish(Path::from(format!("{}/loadavg/1m", base)), init_loadavg.one)?;
    let loadavg5 = publisher
        .publish(Path::from(format!("{}/loadavg/5m", base)), init_loadavg.five)?;
    let loadavg15 = publisher
        .publish(Path::from(format!("{}/loadavg/15m", base)), init_loadavg.fifteen)?;

    let mut interfaces_map: HashMap<String, (Val, Val)> = HashMap::new();
    let mut disks_map: HashMap<String, (Val, Val, Val, Val)> = HashMap::new();
    let mut procs_map = HashMap::new();

    let refresh_interval = Duration::from_secs(opt.interval);
    let deep_refresh_interval = Duration::from_secs(opt.deep_interval);
    let mut last_deep_refresh = Instant::now();

    let task = tokio::spawn(async move {
        loop {
            sleep(refresh_interval).await;
            task::block_in_place(|| {
                if Instant::now().duration_since(last_deep_refresh)
                    >= deep_refresh_interval
                {
                    sys.refresh_networks_list();
                    sys.refresh_disks_list();
                    last_deep_refresh = Instant::now();
                };
                // note: refresh_all() burns about 5% cpu/sec (in release build) with interval = 1 second
                sys.refresh_all()
            });

            let mut batch = publisher.start_batch();
            total_memory.update_changed(&mut batch, sys.total_memory());
            used_memory.update(&mut batch, sys.used_memory());
            total_swap.update_changed(&mut batch, sys.total_swap());
            used_swap.update(&mut batch, sys.used_swap());

            let loadavg = sys.load_average();
            loadavg1.update(&mut batch, loadavg.one);
            loadavg5.update(&mut batch, loadavg.five);
            loadavg15.update(&mut batch, loadavg.fifteen);

            update_network_interface_stats(
                &publisher,
                &mut batch,
                &base,
                &sys,
                &mut interfaces_map,
            )
            .unwrap_or_else(|e| {
                debug!("failed to update network interface stats: {}", e.to_string())
            });

            update_disk_stats(&publisher, &mut batch, &base, &sys, &mut disks_map)
                .unwrap_or_else(|e| {
                    debug!("failed to update disk stats: {}", e.to_string())
                });

            update_procs_stats(&publisher, &mut batch, &base, &sys, &mut procs_map)
                .unwrap_or_else(|e| {
                    debug!("failed to update proc stats: {}", e.to_string())
                });

            batch.commit(None).await
        }
    });
    task.await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let opt = SysinfoOpt::from_args();
    let (cfg, auth) = opt.common.load();
    let res = run(opt, cfg, auth).await;
    match res {
        Err(err) => println!("error: {}", err),
        Ok(_) => (),
    }
}
