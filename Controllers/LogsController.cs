using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Description;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity;
using System.Collections;
using System.Globalization;
using AnamnesisServer.Models;
using System.Security.Claims;

namespace AnamnesisServer.Controllers
{
    [Authorize(Roles = "Admin")]
    public class LogsController : ApiController
    {
        public static int CREATE = 1;
        public static int EDIT = 2;
        public static int DELETE = 3;
        public static int LOGIN = 4;
        public static int LOGOUT = 5;

        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: api/Logs
        public IEnumerable<LogView> GetLog()
        {
            System.Diagnostics.Debug.Write("fecha hoy: " + DateTime.Today);

            List<LogView> logViewList = new List<LogView>();
            foreach (Log log in db.Log.Where(e => e.Date >= DateTime.Today))
            {
                LogView logView = new LogView();
                logView.dateTime = (DateTime)log.Date;
                logView.Date = ((DateTime)log.Date).ToString("yyyy/MM/dd");
                logView.Time = ((DateTime)log.Date).ToString("hh:mm:ss");
                logView.Action = log.Action;
                logView.Object = log.Object;
                logView.User = log.User;
                logView.Role = log.Role;
                logView.Browser = log.Browser;
                logView.Request = log.Request;
                logViewList.Add(logView);
            }

            return logViewList;
        }

        // GET: api/Logs/5
        [ResponseType(typeof(Log))]
        public async Task<IHttpActionResult> GetLog(int id)
        {
            Log log = await db.Log.FindAsync(id);
            if (log == null)
            {
                return NotFound();
            }

            return Ok(log);
        }


        public IEnumerable<LogView> GetLog(string fromDate, string toDate)
        {
            DateTime dtfromDate = DateTime.ParseExact(fromDate, "yyyy/MM/dd", CultureInfo.InvariantCulture);
            DateTime dtToDate = DateTime.ParseExact(toDate, "yyyy/MM/dd", CultureInfo.InvariantCulture);
            dtToDate = dtToDate.AddHours(23.999999);
            System.Diagnostics.Debug.Write("params: " + dtfromDate + " " + dtToDate);

            List<LogView> logViewList = new List<LogView>();
            foreach (Log log in db.Log.Where(e => e.Date >= dtfromDate && e.Date <= dtToDate))
            {
                LogView logView = new LogView();
                logView.Date = ((DateTime)log.Date).ToString("yyyy/MM/dd");
                logView.Time = ((DateTime)log.Date).ToString("hh:mm:ss");
                logView.Action = log.Action;
                logView.Object = log.Object;
                logView.User = log.User;
                logView.Role = log.Role;
                logView.Browser = log.Browser;
                logView.Request = log.Request;
                logViewList.Add(logView);
            }

            return logViewList;
        }

        public IEnumerable<LogView> GetLog(string fromDate, string toDate, string user)
        {
            DateTime dtfromDate = DateTime.ParseExact(fromDate, "yyyy/MM/dd", CultureInfo.InvariantCulture);
            DateTime dtToDate = DateTime.ParseExact(toDate, "yyyy/MM/dd", CultureInfo.InvariantCulture);
            dtToDate = dtToDate.AddHours(23.999999);
            System.Diagnostics.Debug.Write("params: " + dtfromDate + " " + dtToDate + " user: " + user);

            List<LogView> logViewList = new List<LogView>();
            foreach (Log log in db.Log.Where(e => e.Date >= dtfromDate && e.Date <= dtToDate && e.User == user))
            {
                LogView logView = new LogView();
                logView.Date = ((DateTime)log.Date).ToString("yyyy/MM/dd");
                logView.Time = ((DateTime)log.Date).ToString("hh:mm:ss");
                logView.Action = log.Action;
                logView.Object = log.Object;
                logView.User = log.User;
                logView.Role = log.Role;
                logView.Browser = log.Browser;
                logView.Request = log.Request;
                logViewList.Add(logView);
            }

            return logViewList;
        }

        // PUT: api/Logs/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutLog(int id, Log log)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != log.Id)
            {
                return BadRequest();
            }

            db.Entry(log).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!LogExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST: api/Logs
        [ResponseType(typeof(Log))]
        public async Task<IHttpActionResult> PostLog(Log log)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.Log.Add(log);
            await db.SaveChangesAsync();

            return CreatedAtRoute("DefaultApi", new { id = log.Id }, log);
        }

        // DELETE: api/Logs/5
        [ResponseType(typeof(Log))]
        public async Task<IHttpActionResult> DeleteLog(int id)
        {
            Log log = await db.Log.FindAsync(id);
            if (log == null)
            {
                return NotFound();
            }

            db.Log.Remove(log);
            await db.SaveChangesAsync();

            return Ok(log);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool LogExists(int id)
        {
            return db.Log.Count(e => e.Id == id) > 0;
        }

        static Dictionary<int, string> options = new Dictionary<int, string>()
        {
            { 1, "create"},
            { 2, "edit"},
            { 3, "delete"},
            { 4, "login"},
            { 5, "logout"}
        };

        public static String infoBrowser()
        {
            String msg = "";
            try
            {
                msg += "Name: " + HttpContext.Current.Request.Browser.Browser + ", ";
                msg += "Version: " + HttpContext.Current.Request.Browser.Version + ", ";
                msg += "CookieSupport: " + HttpContext.Current.Request.Browser.Cookies + ", ";
                msg += "JSSupport: " + (HttpContext.Current.Request.Browser.EcmaScriptVersion.Major > 0) + ", ";
                msg += "Platform: " + HttpContext.Current.Request.Browser.Platform;
            }
            catch (Exception e) { }
            return msg;
        }

        public static String infoRequest()
        {
            String msg = "";
            try
            {
                msg += "Verb: " + HttpContext.Current.Request.RequestType + ", ";
                msg += "URL: " + HttpContext.Current.Request.Url.Host + HttpContext.Current.Request.Url.PathAndQuery + ", ";
                msg += "HostIP: " + HttpContext.Current.Request.UserHostAddress + HttpContext.Current.Request.UserHostName + ", ";
                msg += "ReffererURL: " + HttpContext.Current.Request.UrlReferrer.Host + HttpContext.Current.Request.UrlReferrer.PathAndQuery;
            }
            catch (Exception e) { }
            return msg;
        }

        public void AddLog(int p, string objeto)
        {
            string method = "";
            Log log = new Log();
            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

            var roleManager = HttpContext.Current.GetOwinContext().Get<ApplicationRoleManager>();

            ApplicationUser user = userManager.FindById(User.Identity.GetUserId());
            if (user == null)
            {
                return;
            }

            if (options.TryGetValue(p, out method))
            {
                log.Action = method;
            }
            log.Object = objeto;
            log.Date = DateTime.Now;
            log.User = user.UserName;
            log.Role = userRole();
            log.Browser = infoBrowser();
            log.Request = infoRequest();
            db.Log.Add(log);
            db.SaveChanges();
        }

        public void AddLog(int p, string objeto, ApplicationUser usuario)
        {
            string method = "";
            Log log = new Log();
            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

            var roleManager = HttpContext.Current.GetOwinContext().Get<ApplicationRoleManager>();

            ApplicationUser user = userManager.FindById(User.Identity.GetUserId());
            if (user == null)
            {
                return;
            }

            if (options.TryGetValue(p, out method))
            {
                log.Action = method;
            }
            log.Object = objeto;
            log.Date = DateTime.Now;
            log.User = user.UserName;
            log.Role = userRole();
            log.Browser = infoBrowser();
            log.Request = infoRequest();
            log.Info = usuario.UserName + ", " + usuario.Name + " " + usuario.LastName;
            db.Log.Add(log);
            db.SaveChanges();
        }
      

        public void AddLog(int p, string objeto, Pacientes paciente)
        {
            string method = "";
            Log log = new Log();
            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

            var roleManager = HttpContext.Current.GetOwinContext().Get<ApplicationRoleManager>();

            ApplicationUser user = userManager.FindById(User.Identity.GetUserId());
            if (user == null)
            {
                return;
            }

            if (options.TryGetValue(p, out method))
            {
                log.Action = method;
            }
            log.Object = objeto;
            log.Date = DateTime.Now;
            log.User = user.UserName;
            log.Role = userRole();
            log.Browser = infoBrowser();
            log.Request = infoRequest();
            log.Info = paciente.Nit + ", "  + paciente.Name + " " + paciente.LastName;
            db.Log.Add(log);
            db.SaveChanges();
        }

        public void AddLogLogin(int p, string objeto, ApplicationUser user)
        {
            string method = "";
            Log log = new Log();
            if (options.TryGetValue(p, out method))
            {
                log.Action = method;
            }
            log.Object = objeto;
            log.Date = DateTime.Now;
            log.User = user.UserName;
            String role = "";
            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            IList<String> roles = userManager.GetRoles(user.Id);
            foreach (String obj in roles)
            {
                role += obj;
            }
            log.Role = role;
            log.Browser = infoBrowser();
            log.Request = infoRequest();
            db.Log.Add(log);
            db.SaveChanges();
        }

        public String userRole()
        {
            String role = "";
            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            IList<String> roles = userManager.GetRoles(User.Identity.GetUserId());
            foreach (String obj in roles)
            {
                role += obj;
            }
            return role;

        }
    }
}