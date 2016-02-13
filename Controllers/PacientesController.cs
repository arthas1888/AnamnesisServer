using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Description;
using AnamnesisServer.Models;

namespace AnamnesisServer.Controllers
{
    [Authorize]
    [RoutePrefix("api/Pacientes")]
    public class PacientesController : ApiController
    {
        private string modelo = new Pacientes().GetType().Name;
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: api/Pacientes
        public IQueryable<Pacientes> GetPacientes()
        {
            return db.Pacientes;
        }

        // POST: api/Pacientes/Consult
        [Route("Consult")]
        [AllowAnonymous]
        public IHttpActionResult ConsultPacientes(ConsultPacientModel model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            string value = model.Value;
            //System.Diagnostics.Debug.Write("entra, value: " + value);            
            int entero;
            List<ConsultPacientOutputModel> pacientes = new List<ConsultPacientOutputModel>();
            if (int.TryParse(value, out entero))
            {
                pacientes = db.Database.SqlQuery<ConsultPacientOutputModel>(
                     "SELECT \"Id\", CONCAT_WS(' ', \"Name\", \"LastName\") as FullName, \"Nit\" FROM dbo.\"Pacientes\" WHERE \"Nit\" ILIKE {0}",
                     "%" + value + "%").ToList();
            }
            else
            {
                pacientes = db.Database.SqlQuery<ConsultPacientOutputModel>(
                     "SELECT \"Id\", CONCAT_WS(' ', \"Name\", \"LastName\") as FullName, \"Nit\" FROM dbo.\"Pacientes\" WHERE CONCAT_WS(' ', \"Name\", \"LastName\") ILIKE {0}",
                     "%" + value + "%").ToList();
            }
            return Ok(pacientes);
        }

        // GET: api/Pacientes/5
        [ResponseType(typeof(Pacientes))]
        public async Task<IHttpActionResult> GetPacientes(int id)
        {
            Pacientes pacientes = await db.Pacientes.FindAsync(id);
            if (pacientes == null)
            {
                return NotFound();
            }

            return Ok(pacientes);
        }

        // GET: api/Pacientes/Consultar/
        [Route("Consultar")]
        [ResponseType(typeof(Pacientes))]

        public IHttpActionResult PostPaciente(ConsultPacientModel model)
        {
            Pacientes pacientes = db.Pacientes.SingleOrDefault(e => e.Nit == model.Value);
            if (pacientes == null || pacientes.Equals(""))
            {
                return NotFound();
            }

            return Ok(pacientes);
        }

        // PUT: api/Pacientes/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutPacientes(int id, Pacientes pacientes)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != pacientes.Id)
            {
                return BadRequest();
            }

            db.Entry(pacientes).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!PacientesExists(id))
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

        // POST: api/Pacientes
        [ResponseType(typeof(Pacientes))]
        public async Task<IHttpActionResult> PostPacientes(Pacientes pacientes)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (PacientesExists(pacientes.Nit))
            {
                return BadRequest("Paciente ya existe.");
            }
            pacientes.CreateDate = DateTime.Now;
            db.Pacientes.Add(pacientes);
            await db.SaveChangesAsync();
            new LogsController().AddLog(LogsController.CREATE, modelo, pacientes);
            return CreatedAtRoute("DefaultApi", new { id = pacientes.Id }, pacientes);
        }

        // POST: api/Pacientes/Edit
        [Route("Edit")]
        [ResponseType(typeof(Pacientes))]
        public async Task<IHttpActionResult> PostEditPacientes(Pacientes pacientes)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            if (!PacientesExists(pacientes.Id))
            {
                return BadRequest();
            }

            db.Entry(pacientes).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!PacientesExists(pacientes.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
            new LogsController().AddLog(LogsController.EDIT, modelo, pacientes);
            return StatusCode(HttpStatusCode.NoContent);
        }

        // DELETE: api/Pacientes/5
        [ResponseType(typeof(Pacientes))]
        public async Task<IHttpActionResult> DeletePacientes(int id)
        {
            Pacientes pacientes = await db.Pacientes.FindAsync(id);
            if (pacientes == null)
            {
                return NotFound();
            }

            db.Pacientes.Remove(pacientes);
            await db.SaveChangesAsync();

            return Ok(pacientes);
        }

        // DELETE: api/Pacientes/Delete
        [Route("Delete")]
        [ResponseType(typeof(Pacientes))]
        public async Task<IHttpActionResult> PostDelete(DeletePacienteModel model)
        {
            //System.Diagnostics.Debug.Write("entra2");
            Pacientes pacientes = await db.Pacientes.FindAsync(model.Id);
            if (pacientes == null)
            {
                return NotFound();
            }

            db.Pacientes.Remove(pacientes);
            
            new LogsController().AddLog(LogsController.DELETE, modelo, pacientes);
            await db.SaveChangesAsync();
            return Ok(pacientes);

        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool PacientesExists(int id)
        {
            return db.Pacientes.Count(e => e.Id == id) > 0;
        }

        private bool PacientesExists(string Nit)
        {
            return db.Pacientes.Count(e => e.Nit == Nit) > 0;
        }
    }
}