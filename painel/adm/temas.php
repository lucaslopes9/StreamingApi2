<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('TemplateTema');
$VerificarAcesso = VerificarAcesso('template', $ColunaAcesso);
$TemplateTema = $VerificarAcesso[0];

if($TemplateTema == 'S'){
	
$SQL = "SELECT TemaPainel FROM site_config";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
$Ln = $SQL->fetch();
$TemaPainel = empty($Ln['TemaPainel']) ? "theme-default" : $Ln['TemaPainel'];
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['template']; ?></li>
                    <li class="active"><?php echo $_TRA['temas']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="content-frame">   
          
          <div class="content-frame-top">                        
           <div class="page-title">                    
          <h2><span class="fa fa-th-large"></span> <?php echo $_TRA['temas']; ?></h2>
          </div>                                      
             </div>
                
                    <div style="margin:50px;">
                        <div class="gallery" id="links" style="margin:30px 0px;">
                        
                        <a class="gallery-item <?php if($TemaPainel == "theme-dark"){ echo "active"; } ?>" href="img/leiaute/theme-dark.jpg" title="Dark" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-dark.jpg" alt="Dark"/>
                                    <?php
									if($TemaPainel != "theme-dark"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-dark"><i class="fa fa-check"></i></span></li>
                                    </ul>  
                                    <?php
									}
									?>                                       
                                </div>
                                <div class="meta">
                                    <strong>Dark</strong>
                                    <span><?php echo $_TRA['tema']." 1"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-dark-head-light"){ echo "active"; } ?>" href="img/leiaute/theme-dark-head-light.jpg" title="Dark Head Light" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-dark-head-light.jpg" alt="Dark Head Light"/>
                                    <?php
									if($TemaPainel != "theme-dark-head-light"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-dark-head-light"><i class="fa fa-check"></i></span></li>
                                    </ul>    
                                    <?php
									}
									?>                                     
                                </div>
                                <div class="meta">
                                    <strong>Dark Head Light</strong>
                                    <span><?php echo $_TRA['tema']." 2"; ?></span>
                                </div>                                
                            </a>
                             
                            <a class="gallery-item <?php if($TemaPainel == "theme-default"){ echo "active"; } ?>" href="img/leiaute/theme-default.jpg" title="Default" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-default.jpg" alt="Default"/>
                                    <?php
									if($TemaPainel != "theme-default"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-default"><i class="fa fa-check"></i></span></li>
                                    </ul>  
                                    <?php
									}
									?>                                      
                                </div>
                                <div class="meta">
                                    <strong>Default</strong>
                                    <span><?php echo $_TRA['tema']." 3"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-default-head-light"){ echo "active"; } ?>" href="img/leiaute/theme-default-head-light.jpg" title="Default Head Light" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-default-head-light.jpg" alt="Default Head Light"/>
                                    <?php
									if($TemaPainel != "theme-default-head-light"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-default-head-light"><i class="fa fa-check"></i></span></li>
                                    </ul>  
                                    <?php
									}
									?>                                      
                                </div>
                                <div class="meta">
                                    <strong>Default Head Light</strong>
                                    <span><?php echo $_TRA['tema']." 4"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-forest"){ echo "active"; } ?>" href="img/leiaute/theme-forest.jpg" title="Forest" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-forest.jpg" alt="Forest"/>
                                    <?php
									if($TemaPainel != "theme-forest"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-forest"><i class="fa fa-check"></i></span></li>
                                    </ul>     
                                    <?php
									}
									?>                                   
                                </div>
                                <div class="meta">
                                    <strong>Forest</strong>
                                    <span><?php echo $_TRA['tema']." 5"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-forest-head-light"){ echo "active"; } ?>" href="img/leiaute/theme-forest-head-light.jpg" title="Forest Head Light" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-forest-head-light.jpg" alt="Forest Head Light"/>
                                    <?php
									if($TemaPainel != "theme-forest-head-light"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-forest-head-light"><i class="fa fa-check"></i></span></li>
                                    </ul>  
                                    <?php
									}
									?>                                      
                                </div>
                                <div class="meta">
                                    <strong>Forest Head Light</strong>
                                    <span><?php echo $_TRA['tema']." 6"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-light"){ echo "active"; } ?>" href="img/leiaute/theme-light.jpg" title="Light" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-light.jpg" alt="Light"/>
                                    <?php
									if($TemaPainel != "theme-light"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-light"><i class="fa fa-check"></i></span></li>
                                    </ul>      
                                    <?php
									}
									?>                                  
                                </div>
                                <div class="meta">
                                    <strong>Light</strong>
                                    <span><?php echo $_TRA['tema']." 7"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-night"){ echo "active"; } ?>" href="img/leiaute/theme-night.jpg" title="Night" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-night.jpg" alt="Night"/>
                                    <?php
									if($TemaPainel != "theme-night"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-night"><i class="fa fa-check"></i></span></li>
                                    </ul>      
                                    <?php
									}
									?>                                  
                                </div>
                                <div class="meta">
                                    <strong>Night</strong>
                                    <span><?php echo $_TRA['tema']." 8"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-night-head-light"){ echo "active"; } ?>" href="img/leiaute/theme-night-head-light.jpg" title="Night Head Light" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-night-head-light.jpg" alt="Night Head Light"/>
                                    <?php
									if($TemaPainel != "theme-night-head-light"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-night-head-light"><i class="fa fa-check"></i></span></li>
                                    </ul>  
                                    <?php
									}
									?>                                      
                                </div>
                                <div class="meta">
                                    <strong>Night Head Light</strong>
                                    <span><?php echo $_TRA['tema']." 9"; ?></span>
                                </div>                                
                            </a>
                            
                            <a class="gallery-item <?php if($TemaPainel == "theme-serenity"){ echo "active"; } ?>" href="img/leiaute/theme-serenity.jpg" title="Serenity" data-gallery>
                                <div class="image">                              
                                    <img src="img/leiaute/theme-serenity.jpg" alt="Serenity"/>
                                    <?php
									if($TemaPainel != "theme-serenity"){
									?>
                                    <ul class="gallery-item-controls">
                                    	<li><span class="gallery-item-aplicar" value="theme-serenity"><i class="fa fa-check"></i></span></li>
                                    </ul>  
                                    <?php
									}
									?>                                      
                                </div>
                                <div class="meta">
                                    <strong>Serenity</strong>
                                    <span><?php echo $_TRA['tema']." 10"; ?></span>
                                </div>                                
                            </a>
                             
                        </div>
            </div>       
                    <!-- END CONTENT FRAME BODY -->
    </div>
    
    <!-- BLUEIMP GALLERY -->
        <div id="blueimp-gallery" class="blueimp-gallery blueimp-gallery-controls">
          <div class="slides"></div>
          <h3 class="title"></h3>
          <a class="prev">‹</a>
          <a class="next">›</a>
          <a class="close">×</a>
          <a class="play-pause"></a>
          <ol class="indicator"></ol>
        </div>      
        <!-- END BLUEIMP GALLERY -->

		<div id="StatusGeral"></div>      
        
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>        
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>
        
        <script type="text/javascript" src="js/plugins/blueimp/jquery.blueimp-gallery.min.js"></script>
        <script type="text/javascript" src="js/plugins/dropzone/dropzone.min.js"></script>
        <script type="text/javascript" src="js/plugins/icheck/icheck.min.js"></script>
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>  
        <!-- END TEMPLATE -->
        
        <script type='text/javascript'> 
		$(function(){  
 			$(".gallery-item-aplicar").on("click",function(){
				
				var tema = $(this).attr("value"); 
				pageLoadingFrame("show");
				 
				$.post('AtualizarTema.php', {tema: tema}, function(resposta) {
				
				setTimeout(function(){
                        pageLoadingFrame("hide");
						$("#StatusGeral").html(resposta);
                },2000); 
				
				});
				
				return false;
			});
		});
		</script>


    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>