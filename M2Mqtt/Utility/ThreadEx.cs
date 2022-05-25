using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace uPLibrary.Networking.M2Mqtt.Utility
{
	/// <summary>
	/// Tucker Thread simple version with reduced functions
	/// </summary>
	/// <remarks>
	/// An instance of this class represents a thread.
	/// <example><code><![CDATA[
	/// void MyStartFunc()
	/// {
	///		TThread thread = new TThread(MyThreadFunc);
	///		thread.Started += new TThread.Handler(OnStarted);
	///		thread.Stopped += new TThread.Handler(OnStopped);
	///		thread.StartThread(MyExceptionHandler);
	///		thread.WaitOnTermination();
	/// }
	/// 
	/// void MyThreadFunc()
	/// {
	///		// do sth
	/// }
	/// 
	/// void MyExceptionHandler(Exception e)
	/// {
	///		// do sth.
	/// }
	/// 
	/// void OnStarted()
	/// {
	///		// do sth
	/// }
	/// 
	/// void OnStopped()
	/// {
	///		// do sth
	/// }
	/// 
	/// 
	/// ]]></code>
	/// </example>
	/// 
	/// </remarks>
	public class ThreadEx
	{
		#region === Delegates =====================================================================

		/// <summary>
		/// delegate for Exception notification
		/// </summary>
		/// <param name="e"></param>
		public delegate void ExceptionHandler(Exception e);

		/// <summary>
		/// delegate for simple event notification
		/// </summary>
		public delegate void Handler();

		/// <summary>
		/// delegate for thread methods
		/// </summary>
		public delegate void ThreadMethod(ThreadEx thread);
		#endregion

		#region === Events =====================================================================

		/// <summary>
		/// Thread has been started
		/// </summary>
		/// <remarks>
		/// In your handler you may not call WaitOnTermination().
		/// </remarks>
		public event Handler Started = delegate() { };

		/// <summary>
		/// thread stopped. You may run Start method
		/// </summary>
		/// <remarks>
		/// In your handler you may even call Open(), WaitOnTermination() and so on.
		/// </remarks>
		public event Handler Stopped = delegate() { };

		#endregion

		#region === Enumerations =====================================================================

		/// <summary>
		/// thread stati
		/// </summary>
		public enum ThreadStatus
		{
			NOT_RUNNING,
			STARTING,
			RUNNING,
			STOPPING
		}
		#endregion

		#region === Variables & Properties =====================================================================

			private ThreadMethod threadMethod;
			private string threadName;
			protected object syncObj = new object();
			
			private Thread thread;
			private ExceptionHandler exceptionHandler;
			private ThreadStatus status;

			/// <summary>
			/// thread status
			/// </summary>
			public string Name
			{
				get
				{
					return threadName;
				}
			}
			
			public bool MustStop
			{
				get
				{
					return Status == ThreadStatus.STOPPING;	
				}
			}

			public bool IsRunning
			{
				get
				{
					return Status != ThreadStatus.NOT_RUNNING;
				}
			}


			/// <summary>
			/// thread status
			/// </summary>
			public ThreadStatus Status
			{
				get
				{
					return status;
				}
			}

			/// <summary>
			/// The priority of the thread (only valid if thread is running)
			/// </summary>
			public ThreadPriority Priority
			{
				get
				{
					if (thread != null)
						return thread.Priority;
					else
						return ThreadPriority.Normal;
				}
				set
				{
					if (thread != null)
						thread.Priority = value;
				}
			}

			/// <summary>
			/// The managed thread id of the internal thread
			/// </summary>
			public int ManagedThreadId
			{
				get
				{
					lock(syncObj)
					{
						if (status == ThreadStatus.NOT_RUNNING)
							return -1;
						else
							return thread.ManagedThreadId;
					}
				}
			}

			/// <summary>Optional tag/information for the thread method</summary>
			private object tag;
			/// <summary>Optional tag/information for the thread method</summary>
			public object Tag
			{
				get { return tag; }
				set { tag = value; }
			}
			
		#endregion

		#region === Constructors =====================================================================
		
			/// <summary>
			/// constructor
			/// </summary>
			/// <param name="threadMethod">
			/// the method which shoul be executed by the thread
			/// </param>
			public ThreadEx(ThreadMethod threadMethod, string threadName)
			{
				this.threadMethod = threadMethod;
				this.threadName = threadName;
			}

		#endregion

		#region === Methods =====================================================================

			/// <summary>
			/// Starts the thread
			/// </summary>
			/// <remarks>
			/// Results in signaling event Started.
			/// May be called even, if thread is already started or starting.
			/// Afterwards thread is minimum on status STARTING.
			/// </remarks>
			/// <param name="priority">
			/// priority of thread (relative to process priority)
			/// </param>
			/// <returns>
			/// true, if thread wasn't running.
			/// false, if thread was allready started, starting or stopping.
			/// </returns>
			public bool StartThread(ThreadPriority priority)
			{
				return StartThread(null, priority);
			}

			/// <summary>
			/// initiates starting the thread.
			/// </summary>
			/// <param name="threadMethod">
			/// the thread method, which should be started.
			/// </param>
			/// <remarks>
			/// Results in signaling event Started.
			/// May be called even, if thread is already started or starting.
			/// Afterwards thread is minimum on status STARTING.
			/// </remarks>
			/// <param name="exHandler">
			/// handler for uncaught exceptions.
			/// In your handler you may even call Close(), WaitOnTermination() and so on.
			/// </param>
			/// <param name="priority">
			/// priority of thread (relative to process priority)
			/// </param>
			/// <returns>
			/// true, if thread wasn't running.
			/// false, if thread was allready started, starting or stopping.
			/// </returns>
			public bool StartThread(ExceptionHandler exHandler, ThreadPriority priority)
			{
				lock(syncObj)
				{

					if (status != ThreadStatus.NOT_RUNNING)
						return false;

					exceptionHandler = exHandler;
					status = ThreadStatus.STARTING;

					thread = new Thread(InternalThreadMethod);
					thread.Name = threadName;
					thread.Priority = priority;

					thread.Start();

					return true;


				}
			}

			/// <summary>
			/// Initiates stopping the thread.
			/// Sets thread status on STOPPING
			/// </summary>
			public void StartStop()
			{
				lock(syncObj)
				{
					if (status != ThreadStatus.NOT_RUNNING)
						status = ThreadStatus.STOPPING;
				}
			}

			/// <summary>
			/// Waits at maximum <paramref name="maxWaitTime"/> milliseconds on 
			/// thread status ThreadStatus.NOT_RUNNING.
			/// Doesn't poll. Doesn't stop the thread - is just waiting
			/// </summary>
			/// <param name="maxWaitTime">The maximum time to wait for thread terminition (ms)</param>
			/// <param name="forceThreadStop">If <c>true</c> the thread waiting on terminition on will be aborted if it has not finished after maximum waiting time; otherwise the thread will not be aborted but the function will not block anylonger</param>
			public void WaitOnTermination(int maxWaitTime, bool forceThreadStop)
			{
				Thread currentThread;
				lock(syncObj)
				{
					if (status == ThreadStatus.NOT_RUNNING)
						return;
					currentThread = thread;
				}

				// TODO: NullRef-Exception may occure here in case of fast reconnect...!!!??? => Analyse and fix!

				if (!currentThread.Join(maxWaitTime))
				{
					if (forceThreadStop)
					{
						currentThread.Abort();
						currentThread.Join(maxWaitTime);
					}
				}
			}

			private void Terminate(ref bool bTerminated)
			{
				if (!bTerminated)
				{
					lock(syncObj)
					{
						status = ThreadStatus.NOT_RUNNING;
						thread = null;
						bTerminated = true;
					}
					Stopped();
				}
			}

			/// <summary>
			/// internal thread method, which calls user defined thread method 
			/// _ThreadMethod.
			/// </summary>
			/// <remarks>
			/// Sets the thread status RUNNING and STOPPED.
			/// In case of uncaught exceptions this thread method 
			/// calls the user defined exception handler.
			/// </remarks>
			protected virtual void InternalThreadMethod()
			{
				bool bTerminated = false;

				try
				{
					if (status == ThreadStatus.STARTING)
						status = ThreadStatus.RUNNING;
					Started();
					if (threadMethod != null)
						threadMethod(this);
				}
	//#if !DEBUG
				catch (Exception e)
				{
					Terminate(ref bTerminated);
					if (exceptionHandler != null)
					{
						exceptionHandler(e);
					}
				}
	//#endif
				finally
				{
					// Terminate, if not terminated already
					Terminate(ref bTerminated);
				}
			}

		#endregion
	}
}
