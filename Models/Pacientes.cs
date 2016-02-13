using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace AnamnesisServer.Models
{
    public class Pacientes
    {
        public int Id { get; set; }

        [Required]
        public DateTime BirthDate { get; set; }

        [Required]
        public string Nit { get; set; }

        [Required]
        public string Name { get; set; }

        [Required]
        public string LastName { get; set; }

        [Display(Name = "Correo Electronico")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        public string Contact { get; set; }

        [Required]
        public string PhoneNumber { get; set; }

        [Display(Name = "Sistema de Salud")]
        public string HealthCare { get; set; }
        [Required]
        public string RH { get; set; }

        [Required]
        public string Gender { get; set; }

        public string Allergy { get; set; }

        [Display(Name = "Medicamentos Permanentes")]
        public string Medicines { get; set; }

        [Display(Name = "Enfermedades Importantes")]
        public string ImportantIllness { get; set; }

        [Display(Name = "Antecedentes Clinicos")]
        public string MedicalHistory { get; set; }

        public DateTime CreateDate { get; set; }
    }

    public class DeletePacienteModel
    {
        [Required]
        [Display(Name = "Id")]
        public int Id { get; set; }
    }

    public class ConsultPacientModel
    {
        [Required]
        public string Value { get; set; }
    }

    public class ConsultPacientOutputModel
    {
        public int Id { get; set; }
        public string FullName { get; set; }
        public string Nit { get; set; }
    }
}