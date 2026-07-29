using SecureAppLocker.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

//  SCM Handshake.
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "SecureAppLockerService";
});

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();