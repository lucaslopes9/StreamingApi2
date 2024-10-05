<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('TemplatePParede');
$VerificarAcesso = VerificarAcesso('template', $ColunaAcesso);
$TemplatePParede = $VerificarAcesso[0];

if($TemplatePParede == 'S'){
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['template']; ?></li>
                    <li class="active"><?php echo $_TRA['papeldeparede']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="content-frame">   
          
          <div class="content-frame-top">                        
           <div class="page-title">                    
          <h2><span class="fa fa-picture-o"></span> <?php echo $_TRA['papeldeparede']; ?></h2>
          </div>                                      
             </div>
                
                    <div style="margin:50px;">
                        <div class="gallery" id="links" style="margin:30px 0px;">
                        
                        <?php
						
						for($i = 1; $i < 11; $i++){
						echo "
                          <a class=\"gallery-item\" id=\"wall_".$i."\" href=\"img/backgrounds/wall_".$i.".jpg\" title=\"".$_TRA['papeldeparede']." ".$i.""."\" data-gallery>
                                <div class=\"image\">                              
                                    <img src=\"img/backgrounds/wall_".$i.".jpg\" alt=\"".$_TRA['papeldeparede']." ".$i."\" />
                                    <ul class=\"gallery-item-controls\">
                                        <li><span class=\"gallery-item-edit\" value=\"wall_".$i."\"><i class=\"fa fa-pencil\"></i></span></li>
                                    </ul>                                    
                                </div>
                                <div class=\"meta\">
                                    <strong>".$_TRA['papeldeparede']." ".$i."</strong>
                                </div>                                
                            </a>
                          ";
						}
                            
                          ?>
                           
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
		$(".gallery-item-edit").on("click",function(){
			var valor = $(this).attr("value"); 
			
			$.post('ScriptModalEditPapelParede.php', {valor: valor}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
			});
       		 
			 return false;
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