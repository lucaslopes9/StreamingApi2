<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$CadUser = InfoUser(2);
$SQL = "SELECT * FROM cupom WHERE CadUser = :CadUser OR UserDescontar = :UserDescontar";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
$SQL->bindParam(':UserDescontar', $CadUser, PDO::PARAM_STR);
$SQL->execute();
	
$AcessoUser = InfoUser(3);
	
$ColunaAcesso = array('OpcoesCupom');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesCupom = $VerificarAcesso[0];
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li>Cupom</li>
                    <li class="active">Cupom</li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-tags"></span> Cupom</h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
								if($OpcoesCupom == 'S'){
                                	echo "<button onclick=\"Adicionar();\" type=\"button\" class=\"btn btn-info active\">".$_TRA['Adicionar']."</button>";
								}
	
								if( ($AcessoUser == 3) || ($AcessoUser == 4) ){
                                	echo "<button onclick=\"DescontarCupom();\" type=\"button\" class=\"btn btn-success active\">Descontar Cupom</button>";
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
                                   		<th>Status</th>
                                    	<th>Cupom</th>
                                        <th>Dias</th>
                                        <th>Perfil</th>
                                        <?php
										if($OpcoesCupom == 'S'){
										echo "
											<th>Gerado por</th>
                                        	<th>Gerado em</th>
                                        	<th>Descontado por</th>
											";
										}
											
                                        echo "<th>Descontado em</th>";
										
										if($OpcoesCupom == 'S'){
                                        echo "<th>".$_TRA['opcoes']."</th>";
										}
										?>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
										while($Ln = $SQL->fetch()){
											
										if(!empty($Ln['UserDescontar'])){
											$status = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Inválido\">N</span>";
											$UserDescontar = $Ln['UserDescontar'];
											$UserDescontarEm = date('d/m/Y \&\a\g\r\a\v\e\;\s H:i', $Ln['UserDescontarEm']);
										}else{
											$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Válido\">S</span>";
											$UserDescontar = "-";
											$UserDescontarEm = "-";
										}
										
										$perfil = SelecionarPerfil($Ln['perfil']);
											
										echo "
                                        <tr>
											<td>".$status."</td>
											<td>".$Ln['Cupom']."</td>
											<td>".$Ln['dias']."</td>
											<td>".$perfil."</td>
											";
										
										if($OpcoesCupom == 'S'){
										echo "
											<td>".$Ln['CadUser']."</td>
											<td>".date('d/m/Y \&\a\g\r\a\v\e\;\s H:i', $Ln['CriadoEm'])."</td>
											<td>".$UserDescontar."</td>
										";
										}
											
										echo "<td>".$UserDescontarEm."</td>";
										
										if($OpcoesCupom == 'S'){
                                       	echo "<td><div class=\"form-group\">";
										
										echo "<a onclick=\"Deletar('".$Ln['id']."', '".$Ln['Cupom']."');\" class=\"deletar label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
								
										echo "</div></td>";
										}
											
                                        echo "</tr>
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
		if($OpcoesCupom == 'S'){
		?>
		function Deletar(id, cupom){
 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+cupom+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarCupom';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($OpcoesCupom == 'S'){
		?>
		function Adicionar(){
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalAdicionarCupom.php', function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
	
		if( ($AcessoUser == 3) || ($AcessoUser == 4) ){
		?>
		function DescontarCupom(){
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalDescontarCupom.php', function(resposta) {
					
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
	echo Redirecionar('login.php');
}
?>