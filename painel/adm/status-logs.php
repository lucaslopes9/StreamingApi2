<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('StatusLogs');
$VerificarAcesso = VerificarAcesso('status', $ColunaAcesso);
$StatusOnline = $VerificarAcesso[0];

if($StatusOnline == 'S'){
	$CadUser = InfoUser(2);
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['sdu']; ?></li>
                    <li class="active"><?php echo $_TRA['Logs']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-certificate"></span> <?php echo $_TRA['Logs']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default PanelStatus">
                                <div class="panel-heading ClassExibirStatus">
                                
               					   <h3 class="panel-title">
                                	<select class="form-control select" id="caduser" name="caduser">
                                    	<?php echo SelecionarArvoreAll($CadUser); ?>
                                     </select>
                                    </h3>
                                    
                                    <h3 class="panel-title">
                                	<select class="form-control select" id="rev" name="rev">
                                    	<option value="N"><?php echo $_TRA['edr']; ?></option>
                                        <option value="S"><?php echo $_TRA['sim']; ?></option>
                                        <option value="N"><?php echo $_TRA['nao']; ?></option>
                                     </select>
                                    </h3>
                                    
                                    <h3 class="panel-title">
                                	<select class="form-control select" id="status" name="status">
                                    	<option value="T"><?php echo $_TRA['Status']; ?></option>
                                        <option value="T"><?php echo $_TRA['Todos']; ?></option>
                                        <option value="on"><?php echo $_TRA['Online']; ?></option>
                                        <option value="off"><?php echo $_TRA['Ocioso']; ?></option>
                                     </select>
                                    </h3>
                                    
                                    <h3 class="panel-title">
                                	<select class="form-control select" id="perfil" name="perfil">
                                    	<option value="T"><?php echo $_TRA['Perfil']; ?></option>
                                        <?php echo PerfilSelectStatus($CadUser); ?>
                                     </select>
                                    </h3>
                                    
                                    <h3 class="panel-title">
                                    <button type="button" class="ExibirStatus btn btn-success"><?php echo $_TRA['Exibir']; ?></button>
                        			</h3>
                                    
                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                <div class="panel-body">
                                                                
                                    <div id="StatusTabela"></div>
                                    
                                    
                                </div>                             
                            </div>



                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        
    

		<div id="StatusGeral"></div>        
       	<!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>
        
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
                <!-- END TEMPLATE -->   
        
         <script>
		$(function(){  
 			$("button.ExibirStatus").click(function() {
				
				var caduser = $('.ClassExibirStatus select[name="caduser"]').val();
				var rev = $('.ClassExibirStatus select[name="rev"]').val();
				var status = $('.ClassExibirStatus select[name="status"]').val();
				var perfil = $('.ClassExibirStatus select[name="perfil"]').val();
								
					
				var panel = $('.PanelStatus');
       		    panel_refresh(panel);
		
				$.post('EnviarStatusLogs.php', {caduser: caduser, rev: rev, status: status, perfil: perfil}, function(resposta) {
					
					setTimeout(function(){
            			panel_refresh(panel);
        			},500);	

					$("#StatusTabela").html(resposta);
					
				});
			});
		});
</script>
          
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>