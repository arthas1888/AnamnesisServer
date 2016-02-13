using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AnamnesisServer.Models
{
    public class Log
    {
        public int Id { get; set; }

        public DateTime Date { get; set; }

        public String Action { get; set; }

        public String Object { get; set; }

        public String User { get; set; }

        public String Role { get; set; }

        public String Browser { get; set; }

        public String Request { get; set; }

        public String Info { get; set; }
    }

    public class LogView
    {
        public DateTime dateTime { get; set; }

        public String Date { get; set; }

        public String Time { get; set; }

        public String Action { get; set; }

        public String Object { get; set; }

        public String User { get; set; }

        public String Role { get; set; }

        public String Browser { get; set; }

        public String Request { get; set; }
    }
}