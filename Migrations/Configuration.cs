namespace AnamnesisServer.Migrations
{
    using Models;
    using System;
    using System.Collections.Generic;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;

    internal sealed class Configuration : DbMigrationsConfiguration<AnamnesisServer.Models.ApplicationDbContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = true;
        }

        protected override void Seed(AnamnesisServer.Models.ApplicationDbContext context)
        {
            //  This method will be called after migrating to the latest version.

            //  You can use the DbSet<T>.AddOrUpdate() helper extension method 
            //  to avoid creating duplicate seed data. E.g.
            //
            //    context.People.AddOrUpdate(
            //      p => p.FullName,
            //      new Person { FullName = "Andrew Peters" },
            //      new Person { FullName = "Brice Lambson" },
            //      new Person { FullName = "Rowan Miller" }
            //    );
            //

            var roles = new List<ApplicationRole>
            {
                new ApplicationRole {Name = "Admin", Description = "Acceso completo"},
                new ApplicationRole {Name = "Users", Description = "Rol de Usuario"}
            };
            roles.ForEach(s => context.Roles.AddOrUpdate(p => p.Name, s));
            context.SaveChanges();
        }
    }
}
