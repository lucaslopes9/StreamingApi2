<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ServidorcspVisualizar', 'ServidorcspAdicionar', 'ServidorcspConfig', 'ServidorcspInfo', 'ServidorcspBloquear', 'ServidorcspEditar', 'ServidorcspExcluir');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);

$ServidorcspVisualizar = $VerificarAcesso[0];
$ServidorcspAdicionar = $VerificarAcesso[1];
$ServidorcspConfig = $VerificarAcesso[2];
$ServidorcspInfo = $VerificarAcesso[3];
$ServidorcspBloquear = $VerificarAcesso[4];
$ServidorcspEditar = $VerificarAcesso[5];
$ServidorcspExcluir = $VerificarAcesso[6];

if($ServidorcspVisualizar == 'S'){

$SQLConfig = "SELECT id FROM painel_config";
$SQLConfig = $painel_geral->prepare($SQLConfig);
$SQLConfig->execute();
$TotalConfig = count($SQLConfig->fetchAll());

$SQLCSP = "SELECT id, nome, url, porta, usuario, senha, protocolo, maxserver, block FROM painel";
$SQLCSP = $painel_geral->prepare($SQLCSP);
$SQLCSP->execute();
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['CSP']; ?></li>
                    <li class="active"><?php echo $_TRA['SCSP']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-gear"></span> <?php echo $_TRA['SCSP']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
								if($ServidorcspAdicionar == 'S'){
                                echo "<button onclick=\"AdicionarCSP();\" type=\"button\" class=\"Adicionar btn btn-info active\">".$_TRA['Adicionar']."</button>";
								}
								if($ServidorcspConfig == 'S'){
								echo "&nbsp;&nbsp;<button onclick=\"ConfiguracoesCSP();\" type=\"button\" class=\"btn btn-danger active\">".$_TRA['config']."</button>";
								}
                                ?>
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
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="150"><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['ipul']; ?></th>
                                        <th><?php echo $_TRA['Porta']; ?></th>
                                        <th><?php echo $_TRA['Usuario']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['protocolo']; ?></th>										
										<th><?php echo $_TRA['maxserver']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
										while($LnCSP = $SQLCSP->fetch()){
										
										if($LnCSP['block'] == "S"){
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
										}else{
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado'][0]."</span>";
										}
										
										echo "
                                        <tr>
											<td>".$LnCSP['nome'].$status."</td>
                                        	<td>".$LnCSP['url']."</td>
                                        	<td>".$LnCSP['porta']."</td>
                                        	<td>".$LnCSP['usuario']."</td>
                                        	<td>".$LnCSP['senha']."</td>
											<td>".$LnCSP['protocolo']."</td>
											<td>".$LnCSP['maxserver']."</td>
                                       	    <td><div class=\"form-group\">";
								
								if( ($TotalConfig > 0) && ($ServidorcspInfo == 'S') ){
									echo "<a class=\"label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['info']."\" onclick=\"InformacoesCSP('".$LnCSP['id']."');\"><i class=\"fa fa-info-circle\"></i></a>&nbsp;";
								}
								
								if($ServidorcspBloquear == 'S'){
									if($LnCSP['block'] == "S"){
									echo "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\" onclick=\"DesBloquearCSP('".$LnCSP['id']."','".$LnCSP['nome']."');\"><i class=\"fa fa-unlock-alt\"></i></a>&nbsp;";
									}else{
									echo "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\" onclick=\"BloquearCSP('".$LnCSP['id']."','".$LnCSP['nome']."');\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
									}	
								}
								
								if($ServidorcspEditar == 'S'){
									echo "<a onclick=\"EditarCSP('".$LnCSP['id']."');\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
								}
								
								if($ServidorcspExcluir == 'S'){
									echo "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\" onclick=\"DeletarCSP('".$LnCSP['id']."','".$LnCSP['nome']."');\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
								}
								
									echo "</div>
											
											</td>
                                        </tr>
										";
										}
										?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        
    

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
                <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <script type='text/javascript'>  
		<?php
		if($ServidorcspExcluir == 'S'){
		?>
		function DeletarCSP(id, nome){
 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarCSP';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($ServidorcspBloquear == 'S'){
		?>
		function BloquearCSP(id, nome){
			
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdba']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarBloquearCSP';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		
		function DesBloquearCSP(id, nome){
 		
 				var titulo = '<?php echo $_TRA['desbloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdda']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarDesbloquearCSP';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($ServidorcspEditar == 'S'){
		?>
		function EditarCSP(id){
 							
				panel_refresh($(".page-container"));
			
				$.post('ScriptModalPainel.php', {id: id}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($ServidorcspAdicionar == 'S'){
		?>
		function AdicionarCSP(){
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalAdicionarPainel.php', function(resposta) {
				
				setTimeout(panel_refresh($(".page-container")),500);
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($ServidorcspConfig == 'S'){
		?>
		function ConfiguracoesCSP(){
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalConfigPainel.php', function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
				
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($ServidorcspInfo == 'S'){
		?>
		function InformacoesCSP(id){
							
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalInfoPainel.php', {id: id}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		?>
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