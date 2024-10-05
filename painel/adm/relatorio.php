<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesRelatorio');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesRelatorio = $VerificarAcesso[0];

if($OpcoesRelatorio == 'S'){
	$CadUser = InfoUser(2);
	
	$VerificarTipoSAT = VerificarTipo('SAT');
	$VerificarTipoCAB = VerificarTipo('CAB');
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['relatorio']; ?></li>
                    <li class="active"><?php echo $_TRA['relatorio']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-file-text-o"></span> <?php echo $_TRA['relatorio']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default PanelStatus">
                                <div class="panel-heading ClassExibirRelatorio">
                                	
                                   <h3 class="panel-title">
                                   <label class="check"><input name="Ativo" id="Ativo" type="checkbox" class="icheckbox" /> Ativo</label>&nbsp;&nbsp;&nbsp;
                                   <label class="check"><input name="Vencido" id="Vencido" type="checkbox" class="icheckbox" /> Esgotado</label>&nbsp;&nbsp;&nbsp;
                                   <label class="check"><input name="Bloqueado" id="Bloqueado" type="checkbox" class="icheckbox" /> Bloqueado</label>&nbsp;&nbsp;&nbsp;
                                   <label class="check"><input name="EntreData" id="EntreData" type="checkbox" class="icheckbox" /> Pesquisar entre Data?</label>&nbsp;&nbsp;&nbsp;
                                   <label class="check"><input name="Simplificado" id="Simplificado" type="checkbox" class="icheckbox" checked="checked"/> <span style="color:brown; font-weight: bold;">Relatório Simplificado</span></label>
                                   </h3>
                                   
                                   <br /><br />
                                   
               					   <h3 class="panel-title">
                                	<select class="form-control select" id="caduser" name="caduser">
                                    	<?php echo SelecionarArvoreAll($CadUser); ?>
                                     </select>
                                    </h3>
                                    
                                    <h3 class="panel-title">
                                	<select class="form-control select" id="rev" name="rev">
                                    	<option value="S"><?php echo $_TRA['edr']; ?></option>
                                        <option value="S"><?php echo $_TRA['sim']; ?></option>
                                        <option value="N"><?php echo $_TRA['nao']; ?></option>
                                     </select>
                                    </h3>
                                    
                                    <h3 class="panel-title">
                                	<select class="form-control select" id="perfil" name="perfil">
                                    	<option value="T"><?php echo $_TRA['Perfil']; ?></option>
                                        <?php echo PerfilSelectStatus($CadUser); ?>
                                     </select>
                                    </h3>
                                    
                                    <h3 class="panel-title">
                                	<select class="form-control select" id="tipo" name="tipo">
                                    	<option value="T"><?php echo $_TRA['Tipo']; ?></option>
                                        <option value="T"><?php echo $_TRA['Todos']; ?></option>
                                        <?php
										if($VerificarTipoSAT > 0){
										?>
                                        <option value="SAT"><?php echo $_TRA['satelite']; ?></option>
                                        <?php
										}
										
										if($VerificarTipoCAB > 0){
										?>
                                        <option value="CAB"><?php echo $_TRA['cabo']; ?></option>
                                        <?php
										}
										?>
                                     </select>
                                    </h3>
                                    
                                   <h3 class="panel-title">
                                   
                                   <div class="btn-group col-md-3" style="padding:5px 0px 5px 0px;">
                                   		<div class="input-group date">
    							   			<input type="text" id="PesquisaEntreData" name="PesquisaEntreData" class="form-control"/>
        							 		<span class="input-group-addon"><span class="glyphicon glyphicon-calendar"></span></span>
    							  	 	</div>
                                   </div>
                                   
                                   <div class="btn-group" style="padding:5px 0px 5px 5px;">
                                   		<button type="button" class="ExibirRelatorio btn btn-success"><?php echo $_TRA['Exibir']; ?></button>
                                   </div>
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
                                
                            </div> <div id="StatusTabela"></div>

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
        
        <script type="text/javascript" src="js/moment.min.js"></script>
        
        <script type="text/javascript" src="js/daterangepicker.js"></script>
        <link rel="stylesheet" type="text/css" href="css/daterangepicker.css" />

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
		$(function() {
			$('input[name="PesquisaEntreData"]').daterangepicker({
				locale: {
      				format: 'DD/MM/YYYY'
    			}
			});
		});
			
		$(function(){  
 			$("button.ExibirRelatorio").click(function() {
				
				var caduser = $('.ClassExibirRelatorio select[name="caduser"]').val();
				var rev = $('.ClassExibirRelatorio select[name="rev"]').val();
				var perfil = $('.ClassExibirRelatorio select[name="perfil"]').val();
				var tipo = $('.ClassExibirRelatorio select[name="tipo"]').val();	
				
				var EntreData = $('.ClassExibirRelatorio input[type=checkbox][name="EntreData"]:checked').val();
				var Ativo = $('.ClassExibirRelatorio input[type=checkbox][name="Ativo"]:checked').val();
				var Vencido = $('.ClassExibirRelatorio input[type=checkbox][name="Vencido"]:checked').val();
				var Bloqueado = $('.ClassExibirRelatorio input[type=checkbox][name="Bloqueado"]:checked').val();
				var Simplificado = $('.ClassExibirRelatorio input[type=checkbox][name="Simplificado"]:checked').val();
				var PesquisaEntreData = $('.ClassExibirRelatorio input[name="PesquisaEntreData"]').val();
				
				var panel = $('.PanelStatus');
       		    panel_refresh(panel);
		
				$.post('EnviarRelatorio.php', {caduser: caduser, rev: rev, perfil: perfil, tipo: tipo, EntreData: EntreData, Ativo: Ativo, Vencido: Vencido, Bloqueado: Bloqueado, Simplificado: Simplificado, PesquisaEntreData: PesquisaEntreData}, function(resposta) {
					
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