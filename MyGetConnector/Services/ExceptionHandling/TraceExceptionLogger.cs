﻿using System.Web.Http.ExceptionHandling;

namespace MyGetConnector.Services.ExceptionHandling
{
    public class TraceExceptionLogger : ExceptionLogger
    {
        public override void Log(ExceptionLoggerContext context)
        {
            Its.Log.Instrumentation.Log.Write(() => context.ExceptionContext.Exception.ToString());
        }
    }
}
