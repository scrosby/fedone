package org.waveprotocol.wave.examples.fedone.waveserver;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.websocket.WebSocket;
import org.eclipse.jetty.websocket.WebSocketServlet;

import com.google.inject.Inject;
import com.google.inject.name.Named;

import org.waveprotocol.wave.examples.fedone.util.Log;


public class WebSocketServerManager {
  private static final Log LOG = Log.get(WebSocketServerManager.class);

  private final String host;
  private final Integer port;
  
  private final Server server;
  
  @Inject
  public WebSocketServerManager(@Named("websocket_frontend_hostname") String host,
      @Named("websocket_frontend_port") Integer port) {
    this.host = host;
    this.port = port;
    
    this.server = new Server();
    Connector c = new SelectChannelConnector();
    c.setHost(host);
    c.setPort(port);
    
    server.addConnector(c);
    ServletContextHandler context = new ServletContextHandler();
    context.setContextPath("/");
    server.setHandler(context);
    
    context.addServlet(new ServletHolder(new WaveWebSocketServlet()), "/");
  }
  
  public void startServer() {
    try {
      server.start();
    } catch (Exception e) {
      LOG.severe("Error in WebSocket server.", e);
    }
    
  }
  
  public static class WaveWebSocketServlet extends WebSocketServlet {
    protected WebSocket doWebSocketConnect(HttpServletRequest request, String protocol)
    {
      return null;
    }
  }
}