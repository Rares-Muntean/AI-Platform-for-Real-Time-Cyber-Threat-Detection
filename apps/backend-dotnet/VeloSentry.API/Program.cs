using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);
var AllowPythonService = "_allowPythonService";
var AllowNuxtFrontend = "_allowNuxtFrontend";

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: AllowPythonService,
        policy =>
        {
            policy.WithOrigins("http://localhost:8080");
        });

    options.AddPolicy(name: AllowNuxtFrontend,
        policy =>
        {
            policy.WithOrigins("http://localhost:5000")
        });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors(AllowPythonService);

app.UseAuthorization();

app.MapControllers();

app.Run();
