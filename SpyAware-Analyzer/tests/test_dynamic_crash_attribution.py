"""Unit tests for Crash Attribution in Dynamic Analysis Stage 2B.

Verifies strict correlation of crash telemetry to target packages, ensuring
unrelated system crashes, generic fatal exceptions, and normal teardown/force-stop
routines are never misattributed to the analyzed application.
"""

import pytest
from analyzers.dynamic.models import RuntimeBehaviorStatus
from analyzers.dynamic.observer import DynamicObserver


@pytest.fixture
def observer():
    return DynamicObserver()


def test_crash_attribution_target_androidruntime_fatal(observer):
    """Scenario 1: AndroidRuntime crash explicitly naming the target package -> OBSERVED."""
    logcat = """
    01-01 12:00:00.100  1000  1000 E AndroidRuntime: FATAL EXCEPTION: main
    01-01 12:00:00.101  1000  1000 E AndroidRuntime: Process: com.target.sample, PID: 4321
    01-01 12:00:00.102  1000  1000 E AndroidRuntime: java.lang.NullPointerException: Attempt to invoke virtual method
    01-01 12:00:00.103  1000  1000 E AndroidRuntime: 	at com.target.sample.MainActivity.onCreate(MainActivity.java:18)
    """
    crashed, evidence, desc = observer.analyze_crash_attribution(
        logcat_text=logcat,
        package_name="com.target.sample",
        target_pids=["4321"],
    )
    assert crashed is True
    assert "com.target.sample" in evidence or "Process: com.target.sample" in evidence

    # Verify in observe_stage_2b
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.sample",
        launch_success=True,
        logcat_text=logcat,
        target_pids=["4321"],
    )
    assert rb["crash"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert any(o.type == "APPLICATION_CRASHED" for o in obs)
    assert score == 0.0  # Crash does not inflate surveillance score


def test_crash_attribution_unrelated_package_crash(observer):
    """Scenario 2: AndroidRuntime crash belonging to an unrelated package -> NOT_OBSERVED."""
    logcat = """
    01-01 12:00:00.100  1000  1000 E AndroidRuntime: FATAL EXCEPTION: main
    01-01 12:00:00.101  1000  1000 E AndroidRuntime: Process: com.google.android.gms, PID: 9999
    01-01 12:00:00.102  1000  1000 E AndroidRuntime: java.lang.RuntimeException: GMS crash
    01-01 12:00:00.103  1000  1000 E AndroidRuntime: 	at com.google.android.gms.internal.Foo.bar(Foo.java:42)
    """
    crashed, evidence, desc = observer.analyze_crash_attribution(
        logcat_text=logcat,
        package_name="com.target.sample",
        target_pids=["4321"],
    )
    assert crashed is False
    assert evidence is None

    # Verify in observe_stage_2b
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.sample",
        launch_success=True,
        logcat_text=logcat,
        target_pids=["4321"],
    )
    assert rb["crash"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert not any(o.type == "APPLICATION_CRASHED" for o in obs)


def test_crash_attribution_generic_fatal_exception_without_package(observer):
    """Scenario 3: Generic FATAL EXCEPTION without package or PID attribution -> NOT_OBSERVED."""
    logcat = """
    01-01 12:00:00.100  1000  1000 E AndroidRuntime: FATAL EXCEPTION: UnknownThread
    01-01 12:00:00.102  1000  1000 E AndroidRuntime: java.lang.OutOfMemoryError: Failed to allocate
    """
    crashed, evidence, desc = observer.analyze_crash_attribution(
        logcat_text=logcat,
        package_name="com.target.sample",
        target_pids=["4321"],
    )
    assert crashed is False
    assert evidence is None

    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.sample",
        launch_success=True,
        logcat_text=logcat,
        target_pids=["4321"],
    )
    assert rb["crash"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert not any(o.type == "APPLICATION_CRASHED" for o in obs)


def test_crash_attribution_force_stop_cleanup_not_crash(observer):
    """Scenario 4: Target process force-stop during cleanup -> NOT_OBSERVED."""
    logcat = """
    01-01 12:00:05.100  1000  1000 I ActivityManager: Force stopping com.target.sample appid=10150 user=0: from pid 1234
    01-01 12:00:05.101  1000  1000 I ActivityManager: Killing 4321:com.target.sample/u0a150 (adj 0): stop com.target.sample
    01-01 12:00:05.102  1000  1000 I ActivityManager: Process com.target.sample (pid 4321) has died: empty
    """
    crashed, evidence, desc = observer.analyze_crash_attribution(
        logcat_text=logcat,
        package_name="com.target.sample",
        target_pids=["4321"],
    )
    assert crashed is False
    assert evidence is None

    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.sample",
        launch_success=True,
        logcat_text=logcat,
        target_pids=["4321"],
    )
    assert rb["crash"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert not any(o.type == "APPLICATION_CRASHED" for o in obs)


def test_crash_attribution_target_fatal_and_process_termination(observer):
    """Scenario 5: Target process disappearance after genuine fatal exception -> OBSERVED."""
    logcat = """
    01-01 12:00:02.000  1000  1000 E AndroidRuntime: FATAL EXCEPTION: main
    01-01 12:00:02.001  1000  1000 E AndroidRuntime: Process: com.target.sample, PID: 4321
    01-01 12:00:02.002  1000  1000 E AndroidRuntime: java.lang.ClassNotFoundException: Didn't find class com.target.sample.MainActivity
    01-01 12:00:02.050  1000  1000 I ActivityManager: Process com.target.sample (pid 4321) has died: crash
    """
    # At launch PID was 4321, but at dump time process table is empty (process disappeared)
    crashed, evidence, desc = observer.analyze_crash_attribution(
        logcat_text=logcat,
        package_name="com.target.sample",
        target_pids=["4321"],
        process_text="",  # process is gone
    )
    assert crashed is True
    assert "com.target.sample" in evidence

    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.sample",
        launch_success=True,
        logcat_text=logcat,
        process_text="",
        target_pids=["4321"],
    )
    assert rb["crash"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert rb["process"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert score == 0.0


def test_crash_attribution_system_process_crash(observer):
    """Scenario 6: System process crash (system_server / system) -> NOT_OBSERVED."""
    logcat = """
    01-01 12:00:00.100  1000  1000 E AndroidRuntime: FATAL EXCEPTION: main
    01-01 12:00:00.101  1000  1000 E AndroidRuntime: Process: system, PID: 1000
    01-01 12:00:00.102  1000  1000 E AndroidRuntime: java.lang.IllegalStateException: System server failure
    01-01 12:00:00.103  1000  1000 E AndroidRuntime: 	at com.android.server.am.ActivityManagerService.crash(AMS.java:100)
    """
    crashed, evidence, desc = observer.analyze_crash_attribution(
        logcat_text=logcat,
        package_name="com.target.sample",
        target_pids=["4321"],
    )
    assert crashed is False
    assert evidence is None

    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.sample",
        launch_success=True,
        logcat_text=logcat,
        target_pids=["4321"],
    )
    assert rb["crash"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert not any(o.type == "APPLICATION_CRASHED" for o in obs)


def test_crash_attribution_normal_successful_execution(observer):
    """Scenario 7: Normal successful execution without crash -> NOT_OBSERVED."""
    logcat = """
    01-01 12:00:01.000  1000  1000 I ActivityTaskManager: START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10000000 cmp=com.target.sample/.MainActivity}
    01-01 12:00:01.200  1000  1000 I ActivityTaskManager: Displayed com.target.sample/.MainActivity: +180ms
    01-01 12:00:02.000  4321  4321 D MainActivity: Application initialized successfully
    """
    process_text = "u0_a150 4321 800 1200000 45000 0 0 S com.target.sample"

    crashed, evidence, desc = observer.analyze_crash_attribution(
        logcat_text=logcat,
        package_name="com.target.sample",
        target_pids=["4321"],
        process_text=process_text,
    )
    assert crashed is False
    assert evidence is None

    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.sample",
        launch_success=True,
        logcat_text=logcat,
        process_text=process_text,
        target_pids=["4321"],
    )
    assert rb["crash"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["process"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert score == 0.0
