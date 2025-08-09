from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask import current_app
import atexit
import logging

scheduler = None

def init_scheduler(app):
    """初始化调度器"""
    global scheduler
    
    # 只在非调试模式或主进程中启动调度器
    if app.debug and not app.config.get('TESTING'):
        import os
        if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
            return
    
    if scheduler is None:
        scheduler = BackgroundScheduler(daemon=True)
        
        # 配置调度器日志
        logging.getLogger('apscheduler').setLevel(logging.WARNING)
        
        with app.app_context():
            if app.config.get('ENABLE_USER_CLEANUP', True):
                interval_hours = app.config.get('CLEANUP_INTERVAL_HOURS', 24)
                
                # 添加定时清理任务
                scheduler.add_job(
                    func=cleanup_users_job,
                    trigger=IntervalTrigger(hours=interval_hours),
                    id='cleanup_inactive_users',
                    name='清理不活跃用户',
                    replace_existing=True,
                    max_instances=1
                )
                
                app.logger.info(f"已启动用户清理定时任务，每 {interval_hours} 小时执行一次")
            else:
                app.logger.info("用户清理功能已禁用，未启动定时任务")
        
        scheduler.start()
        
        # 注册退出时关闭调度器
        atexit.register(lambda: scheduler.shutdown() if scheduler else None)

def cleanup_users_job():
    """定时清理用户的任务函数"""
    from .utils import cleanup_inactive_users
    
    try:
        result = cleanup_inactive_users()
        
        # 记录不活跃用户清理结果
        current_app.logger.info(
            f"定时用户清理完成: 检查 {result['total_checked']} 个用户，"
            f"删除 {result['deleted_count']} 个用户"
        )
        
        # 记录孤儿记录清理结果
        if result.get('orphaned_cleaned', 0) > 0:
            current_app.logger.info(
                f"孤儿记录清理完成: 检查 {result['orphaned_checked']} 个记录，"
                f"清理 {result['orphaned_cleaned']} 个孤儿记录"
            )
        
        if result.get('errors'):
            current_app.logger.error(f"清理过程中出现错误: {'; '.join(result['errors'])}")
            
    except Exception as e:
        current_app.logger.error(f"定时用户清理任务执行失败: {e}", exc_info=True)

def get_scheduler_status():
    """获取调度器状态信息"""
    if scheduler is None:
        return {
            'running': False,
            'jobs': []
        }
    
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            'id': job.id,
            'name': job.name,
            'next_run_time': job.next_run_time.isoformat() if job.next_run_time else None,
            'trigger': str(job.trigger)
        })
    
    return {
        'running': scheduler.running,
        'jobs': jobs
    }

def trigger_cleanup_now():
    """立即触发用户清理任务"""
    if scheduler and scheduler.running:
        try:
            # 手动执行清理任务
            cleanup_users_job()
            return True, "用户清理任务已手动执行"
        except Exception as e:
            current_app.logger.error(f"手动执行用户清理任务失败: {e}")
            return False, f"执行失败: {e}"
    else:
        return False, "调度器未运行"
